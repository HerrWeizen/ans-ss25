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
from ryu.lib.packet import packet, ethernet, arp, ether_types ### KORRIGIERT: ether_types importiert

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
        
        # MAC -> (dpid, port)
        self.hosts = {}

        # IP -> MAC
        self.ip_to_mac = {}

        # DPID -> Datapath
        self.datapaths = {}

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

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info(f"Switch {datapath.id} beigetreten.")
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info(f"Switch {datapath.id} hat verlassen.")

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        self.update_topology()

    @set_ev_cls(event.EventLinkAdd)
    def handler_link_add(self, ev):
        self.update_topology()

    def update_topology(self):
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

    def install_path(self, path, dst_mac):

        self.logger.info(f"Installiere Pfad für Ziel {dst_mac}: {path}")
        
        for i in range(len(path) - 1):
            src_dpid = path[i]
            dst_dpid = path[i+1]
            
            out_port = self.switch_net[src_dpid][dst_dpid]
            dp = self.datapaths[src_dpid]
            parser = dp.ofproto_parser
            
            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 1, match, actions, idle_timeout=10)

        last_switch_dpid = path[-1]
        host_dpid, host_port = self.hosts[dst_mac]
        if last_switch_dpid == host_dpid:
            dp = self.datapaths[last_switch_dpid]
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(host_port)]
            self.add_flow(dp, 1, match, actions, idle_timeout=10)

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
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth_frame = pkt.get_protocol(ethernet.ethernet)

        if not eth_frame:
            return

        if eth_frame.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth_frame.src
        dst_mac = eth_frame.dst

        if src_mac not in self.hosts:
            self.hosts[src_mac] = (dpid, in_port)
            self.logger.info(f"Host {src_mac} an Switch {dpid}, Port {in_port} gelernt.")

        arp_frame = pkt.get_protocol(arp.arp)
        if arp_frame:
            self.ip_to_mac[arp_frame.src_ip] = arp_frame.src_mac
            self._handle_arp(datapath, in_port, eth_frame, arp_frame, msg)
            return
        
        if dst_mac in self.hosts:
            src_dpid, _ = self.hosts[src_mac]
            dst_dpid, _ = self.hosts[dst_mac]

            if src_dpid == dst_dpid:
                _, out_port = self.hosts[dst_mac]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_dst=dst_mac)
                self.add_flow(datapath, 1, match, actions, idle_timeout=10)
            else:
                path = self.dijkstra(src_dpid, dst_dpid)
                if path:
                    self.install_path(path, dst_mac)
                    out_port = self.switch_net[path[0]][path[1]]
                else:
                    out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, 
                                      actions=actions, data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
            datapath.send_msg(out)
        else:
            self.logger.info(f"Ziel-Host {dst_mac} ist unbekannt. Flute das Paket.")
            self._flood(msg)

    def _handle_arp(self, datapath, port, eth_frame, arp_frame, msg):
        if arp_frame.opcode == arp.ARP_REQUEST and arp_frame.dst_ip in self.ip_to_mac:
            target_mac = self.ip_to_mac[arp_frame.dst_ip]
            
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
        else:
            self._flood(msg)

    def _flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, 
                                  actions=actions, data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)