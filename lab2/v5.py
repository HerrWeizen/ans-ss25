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

        # {DPID -> {Neighbor DPID -> Port}}
        self.switches = {}

        # {IP -> (Switch-DPID, connected_port)}
        self.hosts = {}
        
        # DPID -> Datapath for Path installation
        self.datapaths = {}

        # IP -> MAC
        self.arp_table = {}

        # Store all ARP messages for each dpid: {DPID -> {arp_reply: set((tuple)), arp_request: set((tuple))}}
        self.arp_messages = {}

        # Store {src_ip, dst_ip: -> (MSG, DPID)}
        self.ipv4_buffer = {}

    def drop_unwanted_messages(self, msg):
        pkt = packet.Packet(msg.data)
        ether_frame = pkt.get_protocol(ethernet.ethernet)

        if ether_frame.ethertype in [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]:
            return True 
        else:
            return False

    def arp_or_ipv4(self, msg):
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)

        if arp_frame:
            #print("We got an ARP")
            return "ARP"

        elif ipv4_frame:
            #print("We got a IPV4")
            return "IPV4"

        else:
            #print("We got an UNKNOWN")
            return "UNKNOWN"

    def detect_host(self, msg):
        dpid = msg.datapath.id
        in_port = msg.match["in_port"]
        
        switch_ports = self.switches[dpid].values()
        return in_port not in switch_ports 
    
    def check_hosts(self,msg):
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)

        if arp_frame:
            src_ip = arp_frame.src_ip
            return src_ip in self.hosts

        elif ipv4_frame:
            src_ip = ipv4_frame.src
            return src_ip in self.hosts

        else:
            return False

    def add_host(self, msg):
        dpid = msg.datapath.id
        in_port = msg.match["in_port"]
        
        # I hope this will just execute if it's an ARP message
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)

        if arp_frame:
            host_ip = arp_frame.src_ip
        elif ipv4_frame:
            host_ip = ipv4_frame.src
        else:
            return
        
        self.hosts[host_ip] = (dpid, in_port)
        self.logger.info(f"Added Host {host_ip} -> ({dpid}, {in_port})")

    def request_or_reply(self, msg):
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)
        
        if arp_frame.opcode == arp.ARP_REQUEST:
            return "REQUEST"
        elif arp_frame.opcode == arp.ARP_REPLY:
            return "REPLY"

    def check_src_arp_table(self,msg):
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)

        if arp_frame:
            src_ip = arp_frame.src_ip
            return src_ip in self.arp_table

        elif ipv4_frame:
            src_ip = ipv4_frame.src
            return src_ip in self.arp_table

    def check_dst_arp_table(self,msg):
        pkt = packet.Packet(msg.data)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)

        if ipv4_frame:
            dst_ip = ipv4_frame.dst
            return dst_ip in self.arp_table

    def update_arp_table(self, msg):
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)
        ether_frame = pkt.get_protocol(ethernet.ethernet)
        if arp_frame:
            src_ip = arp_frame.src_ip
            src_mac = arp_frame.src_mac
            self.arp_table[src_ip] = src_mac
            self.logger.info(f"Updated ARP-Table via ARP: {src_ip} -> {src_mac}")
        if ipv4_frame:
            src_ip = ipv4_frame.src
            src_mac = ether_frame.src
            self.arp_table[src_ip] = src_mac
            self.logger.info(f"Updated ARP-Table via IPV4: {src_ip} -> {src_mac}")

    def check_arp_messages_of_switch(self, msg):
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)
        
        arp_type = ""
        if arp_frame.opcode == arp.ARP_REQUEST:
            arp_type = "arp_request"
        elif arp_frame.opcode == arp.ARP_REPLY:
            arp_type = "arp_reply"
        else:
            self.logger.error(f"Received unkown ARP Packet Type!")
            return None

        moin = (arp_frame.src_ip, arp_frame.dst_ip, arp_frame.src_mac) in self.arp_messages[dpid][arp_type]

        if moin:
            self.logger.info(f"{arp_type} on Switch {dpid} from {arp_frame.src_ip} to {arp_frame.dst_ip} ALREADY PRESENT")
            return True
        else:
            return False 

    def add_arp_message_to_switch(self, msg):
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)

        arp_type = ""
        if arp_frame.opcode == arp.ARP_REQUEST:
            arp_type = "arp_request"
        elif arp_frame.opcode == arp.ARP_REPLY:
            arp_type = "arp_reply"
        else:
            self.logger.error(f"Received unkown ARP Packet Type!")
            return None
        
        self.arp_messages[dpid][arp_type].add((arp_frame.src_ip, arp_frame.dst_ip, arp_frame.src_mac))
        self.logger.info(f"On Switch {dpid} {arp_type} added: {arp_frame.src_ip, arp_frame.dst_ip, arp_frame.src_mac}")
        return True

    def add_to_ipv4_buffer(self, msg):
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)

        src_ip = ipv4_frame.src
        dst_ip = ipv4_frame.dst

        self.logger.info(f"Added to IPV4-BUFFER: ({src_ip}, {dst_ip}) -> ({msg}, {dpid})")
        self.ipv4_buffer[(src_ip, dst_ip)] = (msg, dpid)
    
    def check_message_in_ipv4_buffer(self, msg):
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)

        src_ip = arp_frame.src_ip
        dst_ip = arp_frame.dst_ip

        return (dst_ip, src_ip) in self.ipv4_buffer

    def get_message_from_ipv4_buffer(self, msg):
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        arp_frame = pkt.get_protocol(arp.arp)

        src_ip = arp_frame.src_ip
        dst_ip = arp_frame.dst_ip

        if (dst_ip, src_ip) in self.ipv4_buffer:
            self.logger.info(f"Retrieve from IPV4-BUFFER: ({dst_ip}, {src_ip}) -> {self.ipv4_buffer((dst_ip, src_ip))}")
            return self.ipv4_buffer((dst_ip, src_ip))
        else:
            self.logger.info(f"There is not a stored IPV4 Packet.")
            return None

    def send_arp_request_based_on_ipv4(self, msg):
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        ether_frame = pkt.get_protocol(ethernet.ethernet)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)

        src_ip = ipv4_frame.src
        dst_ip = ipv4_frame.dst

        arp_request = packet.Packet()
        arp_request.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, src=ether_frame.src, dst='ff:ff:ff:ff:ff:ff'))
        arp_request.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=ether_frame.src, src_ip=src_ip, dst_mac='00:00:00:00:00:00', dst_ip=dst_ip))
        arp_request.serialize()
        
        actions = [msg.datapath.ofproto_parser.OFPActionOutput(msg.datapath.ofproto.OFPP_FLOOD)]
        out = msg.datapath.ofproto_parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.datapath.ofproto.OFP_NO_BUFFER, in_port=msg.datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=arp_request.data)
        
        self.logger.info(f"Start ARP Request flooding from Switch {dpid} for {dst_ip}")
        msg.datapath.send_msg(out)

    def send_arp_request_based_on_arp(self, msg):
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        ether_frame = pkt.get_protocol(ethernet.ethernet)
        arp_frame = pkt.get_protocol(arp.arp)

        src_ip = arp_frame.src_ip
        dst_ip = arp_frame.dst_ip

        arp_request = packet.Packet()
        arp_request.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, src=ether_frame.src, dst='ff:ff:ff:ff:ff:ff'))
        arp_request.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=ether_frame.src, src_ip=src_ip, dst_mac='00:00:00:00:00:00', dst_ip=dst_ip))
        arp_request.serialize()
        
        actions = [msg.datapath.ofproto_parser.OFPActionOutput(msg.datapath.ofproto.OFPP_FLOOD)]
        out = msg.datapath.ofproto_parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.datapath.ofproto.OFP_NO_BUFFER, in_port=msg.datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=arp_request.data)
        
        self.logger.info(f"Send ARP Request flooding from Switch {dpid} for {dst_ip}")
        msg.datapath.send_msg(out)

    def add_message_to_ipv4_buffer(self, msg):
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)

        src_ip = ipv4_frame.src
        dst_ip = ipv4_frame.dst
        self.ipv4_buffer[(src_ip, dst_ip)] = (msg, dpid)

    def send_instant_arp_reply_on_arp_request(self, msg):
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        ether_frame = pkt.get_protocol(ethernet.ethernet)
        arp_frame = pkt.get_protocol(arp.arp)  
        in_port = msg.match["in_port"]

        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(ethertype=ether_frame.ethertype, dst=ether_frame.src, src=ether_frame.dst))
        arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=ether_frame.dst, src_ip=arp_frame.dst_ip, dst_mac=arp_frame.src_mac, dst_ip=arp_frame.src_ip))
        arp_reply.serialize()

        actions = [msg.datapath.ofproto_parser.OFPActionOutput(in_port)]
        out = msg.datapath.ofproto_parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.datapath.ofproto.OFP_NO_BUFFER, in_port=msg.datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=arp_reply.data)

        msg.datapath.send_msg(out)

    def send_ipv4(self, msg, port_to_next_hop):
        dpid = msg.datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        ether_frame = pkt.get_protocol(ethernet.ethernet)
        ipv4_frame = pkt.get_protocol(ipv4.ipv4)

        dst_ip = ipv4_frame.dst
        dst_mac = self.arp_table[dst_ip]

        dst_dpid, dst_port = self.hosts[dst_ip]

        new_pkt = packet.Packet()
        new_pkt.add_protocol(ethernet.ethernet(ethertype=ether_frame.ethertype, src=ether_frame.src, dst=dst_mac))
        new_pkt.add_protocol(ipv4_frame)
        new_pkt.serialize()

        actions = [msg.datapath.ofproto_parser.OFPActionOutput(port_to_next_hop)]
        out = msg.datapath.ofproto_parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.datapath.ofproto.OFP_NO_BUFFER, in_port=msg.datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=new_pkt.data)

        msg.datapath.send_msg(out)

    def send_arp_reply(self, msg, port_to_next_hop):
        dpid = msg.datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        ether_frame = pkt.get_protocol(ethernet.ethernet)
        arp_frame = pkt.get_protocol(arp.arp)

        dst_ip = arp_frame.dst_ip
        dst_mac = self.arp_table[dst_ip]

        dst_dpid, dst_port = self.hosts[dst_ip]

        new_pkt = packet.Packet()
        new_pkt.add_protocol(ethernet.ethernet(ethertype=ether_frame.ethertype, src=ether_frame.src, dst=dst_mac))
        new_pkt.add_protocol(arp_frame)
        new_pkt.serialize()

        actions = [msg.datapath.ofproto_parser.OFPActionOutput(port_to_next_hop)]
        out = msg.datapath.ofproto_parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.datapath.ofproto.OFP_NO_BUFFER, in_port=msg.datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=new_pkt.data)

        msg.datapath.send_msg(out)

    def dijkstra(self, start_node, end_node):
        self.logger.info(f"Dijkstra: Suche Pfad von {start_node} zu {end_node}")
        if start_node not in self.switches or end_node not in self.switches:
            self.logger.info("Start- oder Endknoten ist nicht im Switch-Netzwerk vorhanden!")
            return []
        distances = {node: float('inf') for node in self.switches}
        previous_nodes = {node: None for node in self.switches}
        distances[start_node] = 0
        pq = [(0, start_node)]
        while pq:
            current_distance, current_node = heapq.heappop(pq)
            if current_node == end_node:
                break
            if current_distance > distances[current_node]:
                continue
            for neighbor, port in self.switches[current_node].items():
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
            self.logger.info(f"Kürzester Pfad gefunden: {path}")
            return path
        self.logger.error("Kein Pfad gefunden.")
        return []
        
    def install_path(self, path, dst_ip, src_ip):
        dst_mac = self.arp_table[dst_ip]
        src_mac = self.arp_table[src_ip]

        self.logger.info(f"Installiere Pfad für Ziel {dst_ip}: {path}")

        for i in range(len(path) - 1):
            dp = self.datapaths[path[i]]
            out_port = self.switches[path[i]][path[i+1]]
            match = dp.ofproto_parser.OFPMatch(ipv4_dst=dst_ip, ipv4_src=src_ip, eth_type=ether_types.ETH_TYPE_IP)
            actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 10, match, actions)
            match = dp.ofproto_parser.OFPMatch(arp_tpa=dst_ip, arp_spa=src_ip, eth_type=ether_types.ETH_TYPE_ARP)
            actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 10, match, actions)
            

        last_dp = self.datapaths[path[-1]]
        dst_host_port = self.hosts[dst_ip][1]
        match = last_dp.ofproto_parser.OFPMatch(ipv4_dst=dst_ip, ipv4_src=src_ip, eth_type=ether_types.ETH_TYPE_IP)
        actions = [last_dp.ofproto_parser.OFPActionOutput(dst_host_port)]
        self.add_flow(last_dp, 10, match, actions)
        match = last_dp.ofproto_parser.OFPMatch(arp_tpa=dst_ip, arp_spa=src_ip, eth_type=ether_types.ETH_TYPE_ARP)
        actions = [last_dp.ofproto_parser.OFPActionOutput(dst_host_port)]
        self.add_flow(last_dp, 10, match, actions)

    @set_ev_cls(event.EventSwitchEnter, event.EventLinkAdd)
    def update_topology(self, ev):
        # add all switches to self.switches
        self.switches.clear()

        for switch in get_switch(self, None):
            self.switches[switch.dp.id] = {}
            self.datapaths[switch.dp.id] = switch.dp
            self.arp_messages[switch.dp.id] = {"arp_reply": set(), "arp_request": set()}

        # add all links
        for link in get_link(self, None):
            self.switches[link.src.dpid][link.dst.dpid] = link.src.port_no

        self.logger.info("Topologie aktualisiert.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg

        if self.drop_unwanted_messages(msg):
            return

        # Check if the msg comes from a host, no matter the message
        if self.detect_host(msg):
            print("Host detected")
            if not self.check_hosts(msg):
                print("Not Present")
                self.add_host(msg)
                self.update_arp_table(msg)
            print("Already Present?")
            
        
        message_type = self.arp_or_ipv4(msg)

        if message_type == "UNKNOWN":
            self.logger.info("We got an Unknown ARP or IPV4 message.")
            return

        elif message_type == "ARP":
            
            if self.check_arp_messages_of_switch(msg):
                return
            else: 
                self.add_arp_message_to_switch(msg)
            #print(f"All ARP Messages: {self.arp_messages}" )
            arp_type = self.request_or_reply(msg)
            
            if arp_type == "REQUEST":
                #self.logger.info("We got an ARP Request.")

                if self.check_dst_arp_table(msg):
                    print("Hallo?")
                    if self.detect_host(msg):
                        
                        self.send_instant_arp_reply_on_arp_request(msg)
                        return
                else:
                    print("Hallo!")
                    self.send_arp_request_based_on_arp(msg)
                    return
                

            elif arp_type == "REPLY":
                #self.logger.info("We got an ARP Reply.")
                 
                if self.check_message_in_ipv4_buffer(msg):
                    ipv4_message, _ = self.get_message_from_ipv4_buffer(msg)
                    pkt = packet.Packet(msg.data)
                    ipv4_frame = pkt.get_protocol(ipv4.ipv4)

                    src_ip = ipv4_frame.src
                    dst_ip = ipv4_frame.dst

                    dst_dpid, dst_port = self.hosts[dst_ip]
                    src_dpid = msg.datapath.id

                    path = self.dijkstra(src_dpid, dst_dpid)
                    self.install_path(path, dst_ip, src_ip)
                    self.install_path(path[::-1], src_ip, dst_ip)
                    if len(path) > 1:
                        next_hop = path[1]
                        port_to_next_hop = self.switches[src_dpid][next_hop]
                    else: 
                        port_to_next_hop = self.hosts[dst_ip][1]

                    self.send_ipv4(msg, port_to_next_hop)
                
                # Use dijkstra for reply
                pkt = packet.Packet(msg.data)
                arp_frame = pkt.get_protocol(arp.arp)

                src_ip = arp_frame.src_ip
                dst_ip = arp_frame.dst_ip

                dst_dpid, dst_port = self.hosts[dst_ip]
                src_dpid = msg.datapath.id

                path = self.dijkstra(src_dpid, dst_dpid)
                self.install_path(path, dst_ip, src_ip)
                self.install_path(path[::-1], src_ip, dst_ip)
                if len(path) > 1:
                    next_hop = path[1]
                    port_to_next_hop = self.switches[src_dpid][next_hop]
                else: 
                    port_to_next_hop = self.hosts[dst_ip][1]

                self.send_arp_reply(msg, port_to_next_hop)

        elif message_type == "IPV4":
            #self.logger.info(f"HI! We got a IPV4")
            if self.check_dst_arp_table(msg):
                pkt = packet.Packet(msg.data)
                ipv4_frame = pkt.get_protocol(ipv4.ipv4)

                src_ip = ipv4_frame.src
                dst_ip = ipv4_frame.dst

                dst_dpid, dst_port = self.hosts[dst_ip]
                src_dpid = msg.datapath.id

                path = self.dijkstra(src_dpid, dst_dpid)
                self.install_path(path, dst_ip, src_ip)
                self.install_path(path[::-1], src_ip, dst_ip)
                if len(path) > 1:
                    next_hop = path[1]
                    port_to_next_hop = self.switches[src_dpid][next_hop]
                else: 
                    port_to_next_hop = self.hosts[dst_ip][1]

                self.send_ipv4(msg, port_to_next_hop) 
                return

            else:

                self.logger.info("Destination is not know, send request.")
                self.add_message_to_ipv4_buffer(msg)
                self.send_arp_request_based_on_ipv4(msg)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                          datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"installed flow for {match} and {actions}")