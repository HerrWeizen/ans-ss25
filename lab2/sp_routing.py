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
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import heapq
import topo

class SPRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        self.topo_net = topo.Fattree(4)
        self.adjacency = {}      # Switch connectivity: dpid -> {neighbor_dpid: (cost, port)}
        self.mac_to_port = {}    # Per-switch MAC table: dpid -> {mac: port}
        self.mac_to_switch = {}  # Global MAC location: mac -> dpid
        self.datapaths = {}      # dpid -> datapath object
        self.ports = {}          # Switch ports: dpid -> set(port_nums)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        """Discover network topology and build adjacency matrix"""
        switch_list = get_switch(self, None)
        links = get_link(self, None)
        
        self.adjacency = {}
        self.ports = {}
        self.logger.info("Topology discovery started")

        # Build switch port list (excluding controller port)
        for switch in switch_list:
            dpid = switch.dp.id
            self.ports[dpid] = set()
            for p in switch.ports:
                if p.port_no != switch.dp.ofproto.OFPP_LOCAL:
                    self.ports[dpid].add(p.port_no)

        # Build adjacency matrix with link costs
        for link in links:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no

            # Initialize if needed
            if src_dpid not in self.adjacency:
                self.adjacency[src_dpid] = {}
            if dst_dpid not in self.adjacency:
                self.adjacency[dst_dpid] = {}

            # Store both directions (cost=1 for all links)
            self.adjacency[src_dpid][dst_dpid] = (1, src_port)
            self.adjacency[dst_dpid][src_dpid] = (1, dst_port)

        self.logger.info("Adjacency matrix: %s", self.adjacency)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle new switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        
        # Install default flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected", datapath.id)

    def compute_shortest_path(self, src_dpid, dst_dpid):
        """Dijkstra's algorithm for shortest path in Fat-Tree"""
        if src_dpid not in self.adjacency or dst_dpid not in self.adjacency:
            return None

        # Initialize data structures
        distances = {node: float('inf') for node in self.adjacency}
        previous = {node: None for node in self.adjacency}
        distances[src_dpid] = 0
        queue = [(0, src_dpid)]
        
        while queue:
            current_dist, current_dpid = heapq.heappop(queue)
            
            # Destination reached
            if current_dpid == dst_dpid:
                break
                
            # Explore neighbors
            for neighbor, (cost, _) in self.adjacency[current_dpid].items():
                distance = current_dist + cost
                
                # Found better path
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous[neighbor] = current_dpid
                    heapq.heappush(queue, (distance, neighbor))
        
        # Reconstruct path
        path = []
        current = dst_dpid
        
        while current is not None:
            path.insert(0, current)
            current = previous.get(current)
        
        return path if path and path[0] == src_dpid else None

    def add_flow(self, datapath, priority, match, actions):
        """Install flow entry to switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets at controller"""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if not eth:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        self.logger.info("Packet in %s: %s -> %s port %s", 
                         dpid, src_mac, dst_mac, in_port)

        # Initialize MAC tables for this switch
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        
        # Learn source MAC address
        self.mac_to_port[dpid][src_mac] = in_port
        self.mac_to_switch[src_mac] = dpid

        # Handle broadcast/multicast
        if dst_mac.lower() in ['ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:00']:
            self.flood_packet(msg, in_port)
            return

        # Known destination MAC
        if dst_mac in self.mac_to_switch:
            dst_dpid = self.mac_to_switch[dst_mac]
            
            # Destination on same switch
            if dst_dpid == dpid:
                if dst_mac in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst_mac]
                    self.send_packet(datapath, in_port, out_port, msg.data)
                else:
                    self.flood_packet(msg, in_port)
                return
            
            # Path to destination switch
            path = self.compute_shortest_path(dpid, dst_dpid)
            if not path:
                self.logger.warn("No path to %s via %s", dst_mac, dst_dpid)
                self.flood_packet(msg, in_port)
                return
                
            # Get next hop and output port
            next_hop = path[1]
            if next_hop in self.adjacency[dpid]:
                out_port = self.adjacency[dpid][next_hop][1]
            else:
                self.logger.error("No port to next hop %s from %s", next_hop, dpid)
                self.flood_packet(msg, in_port)
                return
                
            # Install flow entry for this destination
            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)
            
            # Forward current packet
            self.send_packet(datapath, in_port, out_port, msg.data)
            
        else:
            # Unknown destination MAC - flood
            self.flood_packet(msg, in_port)

    def flood_packet(self, msg, in_port):
        """Flood packet to all ports except input port"""
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        out_ports = [p for p in self.ports[dpid] if p != in_port]
        actions = [parser.OFPActionOutput(p) for p in out_ports]
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
        self.logger.debug("Flooding packet from %s port %s", dpid, in_port)

    def send_packet(self, datapath, in_port, out_port, data):
        """Send packet to specific port"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
        self.logger.debug("Sending packet from %s port %d -> %d", 
                          datapath.id, in_port, out_port)