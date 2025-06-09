"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
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
        
        # Initialize the topology with #ports=4
        # self.topo_net = topo.Fattree(4) # Deaktiviert, da 'topo' nicht Teil von Ryu ist
        # {dpid: {neighbor_dpid: port_no to neighbor}}
        self.switch_net = {}
        # IP -> (dpid, port)
        self.hosts = {}
        # DPID -> Datapath
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
            if current_node not in self.switch_net:
                continue
            for neighbor, port in self.switch_net[current_node].items():
                weight = 1
                distance = current_distance + weight
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous_nodes[neighbor] = current_node
                    heapq.heappush(pq, (distance, neighbor))
        path = []
        current = end_node
        while current is not None:
            path.insert(0, current)
            current = previous_nodes.get(current)
        if path and path[0] == start_node:
            self.logger.info(f"Kürzester Pfad gefunden: {path}")
            return path
        else:
            self.logger.error(f"Kein Pfad von {start_node} zu {end_node} gefunden.")
            return []

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info(f"Switch {datapath.id} beigetreten.")

    @set_ev_cls(event.EventSwitchEnter)
    def update_topology(self, ev):
        self.switch_net.clear()
        switches = get_switch(self, None)
        for switch in switches:
            dpid = switch.dp.id
            if dpid not in self.switch_net:
                self.switch_net[dpid] = {}

        links = get_link(self, None)
        for link in links:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            if src_dpid in self.switch_net:
                self.switch_net[src_dpid][dst_dpid] = src_port
        
        self.logger.info("Topologie aktualisiert.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def install_path(self, path, dst_ip):
        dst_mac = self.arp_table[dst_ip]
        self.logger.info(f"Installiere Pfad für Ziel {dst_ip}: {path}")
        for i in range(len(path) - 1):
            src_dpid = path[i]
            dst_dpid = path[i+1]
            
            out_port = self.switch_net[src_dpid][dst_dpid]
            dp = self.datapaths[src_dpid]
            parser = dp.ofproto_parser
            
            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 1, match, actions)

        last_switch_dpid = path[-1]
        host_dpid, host_port = self.hosts[dst_ip]
        if last_switch_dpid == host_dpid:
            dp = self.datapaths[last_switch_dpid]
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(host_port)]
            self.add_flow(dp, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, 
                                instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt_in = packet.Packet(msg.data)
        eth_frame = pkt_in.get_protocol(ethernet.ethernet)
        arp_frame = pkt_in.get_protocol(arp.arp)
        ipv4_frame = pkt_in.get_protocol(ipv4.ipv4)

        if not eth_frame or eth_frame.ethertype == ether_types.ETH_TYPE_LLDP or eth_frame.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        src_mac = eth_frame.src
        dst_mac = eth_frame.dst
        src_ip = None
        dst_ip = None
        if arp_frame:
            src_ip = arp_frame.src_ip
            dst_ip = arp_frame.dst_ip
        elif ipv4_frame:
            src_ip = ipv4_frame.src
            dst_ip = ipv4_frame.dst


        if in_port not in self.switch_net[dpid].values():
            self.hosts[src_ip] = (dpid, in_port) # add host with switch dpid and port to address it
            self.arp_table[src_ip] = src_mac # add arp table entry

        if arp_frame:
            self.arp_table[src_ip] = arp_frame.src_mac
            self.handle_arp(datapath, in_port, eth_frame, arp_frame, msg)
            return
        
        if ipv4_frame:
            self.handle_ipv4(datapath, in_port, eth_frame, ipv4_frame, msg)

    def handle_arp(self, datapath, port, eth_frame, arp_frame, msg):
        dpid = datapath.id
        # If the ARP Request from Host is already known go send a reply to the host directly!
        if arp_frame.opcode == arp.ARP_REQUEST and arp_frame.dst_ip in self.arp_table:
            target_mac = self.arp_table[arp_frame.dst_ip]

            # Check if this ARP Request was already received by the current Switch to stop circle flooding
            if dpid in self.known_arp_requests:
                if arp_frame.dst_ip in self.known_arp_requests[dpid]:
                    return
                else:
                    self.known_arp_requests[dpid].add(arp_frame.dst_ip)
            else:
                self.known_arp_requests[dpid] = set()
                self.known_arp_requests[dpid].add(arp_frame.dst_ip)

            arp_reply = packet.Packet()
            arp_reply.add_protocol(ethernet.ethernet(ethertype=eth_frame.ethertype, dst=eth_frame.src, src=target_mac))
            arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=target_mac, src_ip=arp_frame.dst_ip,
                                           dst_mac=arp_frame.src_mac, dst_ip=arp_frame.src_ip))
            arp_reply.serialize()

            actions = [datapath.ofproto_parser.OFPActionOutput(port)]
            out = datapath.ofproto_parser.OFPPacketOut(datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, 
                                                       in_port=datapath.ofproto.OFPP_CONTROLLER, 
                                                       actions=actions, data=arp_reply.data)
            datapath.send_msg(out)
        # Otherwise flood if Request
        elif arp_frame.opcode == arp.ARP_REQUEST:
            actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
            datapath.send_msg(out)
        # Got a Reply, look into buffer
        elif arp_frame.opcode == arp.ARP_REPLY:
            self.arp_table[arp_frame.src_ip] = arp_frame.src_mac
            if arp_frame.src_ip in self.packet_buffer:
                received_ip_buffer = self.packet_buffer[arp_frame.src_ip]
                for pending_packet in received_ip_buffer:
                    datapath, port, eth_frame, ipv4_frame, msg = pending_packet
                    self.handle_ipv4(datapath, port, eth_frame, ipv4_frame, msg)
                del self.packet_buffer[arp_frame.src_ip]
            else:
                self.logger.info(f"No Pending IP Packages for received ARP Information.")
                return

    def handle_ipv4(self, datapath, port, eth_frame, ipv4_frame, msg):
        dst_ip = ipv4_frame.dst
        if dst_ip not in self.hosts:
            #actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
            #out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
            #datapath.send_msg(out)
            if dst_ip not in self.packet_buffer:
                self.packet_buffer[dst_ip] = []
            for i in self.known_arp_requests.values():
                if dst_ip in i:
                    self.packet_buffer[dst_ip].append((datapath, port, eth_frame, ipv4_frame, msg))
                    self.logger.info(f"IP-Packet was buffered.")
            return

        dst_dpid, port = self.hosts[dst_ip]
        path = self.dijkstra(datapath.id, dst_dpid)
        self.install_path(path, dst_ip)
        
        src_dpid = path[0]
        next_hop = path[1]
        out_port = self.switch_net[src_dpid][next_hop]

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
        datapath.send_msg(out)