from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types, ipv4

from ryu.topology import event
from ryu.topology.api import get_switch, get_link

import heapq

class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        self.switch_net = {}
        self.hosts = {}
        self.datapaths = {}
        self.arp_table = {}
        self.known_arp_requests = {}
        self.packet_buffer = {}

    def dijkstra(self, start_node, end_node):
        self.logger.info(f"Dijkstra: Suche Pfad von {start_node} zu {end_node}")
        if start_node not in self.switch_net or end_node not in self.switch_net:
            self.logger.info("Start- oder Endknoten ist nicht im Switch-Netzwerk vorhanden!")
            return []
        distances = {node: float('inf') for node in self.switch_net}
        previous_nodes = {node: None for node in self.switch_net}
        distances[start_node] = 0
        pq = [(0, start_node)]
        while pq:
            current_distance, current_node = heapq.heappop(pq)
            if current_node == end_node:
                break
            if current_distance > distances[current_node]:
                continue
            for neighbor, port in self.switch_net[current_node].items():
                distance = current_distance + 1
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous_nodes[neighbor] = current_node
                    heapq.heappush(pq, (distance, neighbor))
        path = []
        current = end_node
        while current is not None:
            path.insert(0, current)
            current = previous_nodes[current]
        if path and path[0] == start_node:
            self.logger.info(f"K\u00fcrzester Pfad gefunden: {path}")
            return path
        self.logger.error("Kein Pfad gefunden.")
        return []

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info(f"Switch {datapath.id} beigetreten.")

    @set_ev_cls(event.EventSwitchEnter)
    def update_topology(self, ev):
        self.switch_net.clear()
        for switch in get_switch(self, None):
            self.switch_net[switch.dp.id] = {}
        for link in get_link(self, None):
            self.switch_net[link.src.dpid][link.dst.dpid] = link.src.port_no
        self.logger.info("Topologie aktualisiert.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                          datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def install_path(self, path, dst_ip):
        dst_mac = self.arp_table[dst_ip]
        self.logger.info(f"Installiere Pfad f\u00fcr Ziel {dst_ip}: {path}")
        for i in range(len(path) - 1):
            dp = self.datapaths[path[i]]
            out_port = self.switch_net[path[i]][path[i+1]]
            match = dp.ofproto_parser.OFPMatch(eth_dst=dst_mac)
            actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 1, match, actions)
        last_dp = self.datapaths[path[-1]]
        host_port = self.hosts[dst_ip][1]
        match = last_dp.ofproto_parser.OFPMatch(eth_dst=dst_mac)
        actions = [last_dp.ofproto_parser.OFPActionOutput(host_port)]
        self.add_flow(last_dp, 1, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if not eth or eth.ethertype in [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            self.arp_table[src_ip] = src_mac
            if in_port not in self.switch_net[dpid].values():
                self.hosts[src_ip] = (dpid, in_port)

            self.handle_arp(datapath, in_port, eth, arp_pkt, msg)

        elif ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            if in_port not in self.switch_net[dpid].values():
                self.hosts[src_ip] = (dpid, in_port)
                self.arp_table[src_ip] = src_mac
            self.handle_ipv4(datapath, in_port, eth, ipv4_pkt, msg)

    def handle_arp(self, datapath, port, eth_frame, arp_frame, msg):
        dpid = datapath.id
        if arp_frame.opcode == arp.ARP_REQUEST:
            if arp_frame.dst_ip in self.arp_table:
                target_mac = self.arp_table[arp_frame.dst_ip]
                if dpid not in self.known_arp_requests:
                    self.known_arp_requests[dpid] = set()
                if arp_frame.dst_ip in self.known_arp_requests[dpid]:
                    return
                self.known_arp_requests[dpid].add(arp_frame.dst_ip)

                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(ethertype=eth_frame.ethertype,
                                                        dst=eth_frame.src,
                                                        src=target_mac))
                arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                               src_mac=target_mac,
                                               src_ip=arp_frame.dst_ip,
                                               dst_mac=arp_frame.src_mac,
                                               dst_ip=arp_frame.src_ip))
                arp_reply.serialize()
                actions = [datapath.ofproto_parser.OFPActionOutput(port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=arp_reply.data)
                datapath.send_msg(out)
            else:
                actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                           buffer_id=msg.buffer_id,
                                                           in_port=datapath.ofproto.OFPP_CONTROLLER,
                                                           actions=actions,
                                                           data=msg.data)
                datapath.send_msg(out)
        elif arp_frame.opcode == arp.ARP_REPLY:
            ip = arp_frame.src_ip
            if ip in self.packet_buffer:
                for pkt in self.packet_buffer[ip]:
                    dp, port, eth, ipv4_pkt, msg = pkt
                    self.handle_ipv4(dp, port, eth, ipv4_pkt, msg)
                del self.packet_buffer[ip]

    def handle_ipv4(self, datapath, port, eth_frame, ipv4_frame, msg):
        dst_ip = ipv4_frame.dst
        if dst_ip not in self.hosts:
            if dst_ip not in self.packet_buffer:
                self.packet_buffer[dst_ip] = []
            self.packet_buffer[dst_ip].append((datapath, port, eth_frame, ipv4_frame, msg))
            self.logger.info(f"IP-Paket an {dst_ip} wurde gebuffert.")
            return

        dst_dpid, dst_port = self.hosts[dst_ip]
        path = self.dijkstra(datapath.id, dst_dpid)
        if not path:
            return

        self.install_path(path, dst_ip)
        next_hop = path[1]
        out_port = self.switch_net[datapath.id][next_hop]
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                   buffer_id=msg.buffer_id,
                                                   in_port=datapath.ofproto.OFPP_CONTROLLER,
                                                   actions=actions,
                                                   data=msg.data)
        datapath.send_msg(out)
