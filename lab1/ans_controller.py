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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether, inet
from ryu.lib.packet import ethernet, arp, ipv4, icmp, ether_types, packet # https://ryu.readthedocs.io/en/latest/library_packet.html

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        
        # Layer 2: MAC Learning Table
        self.mac_to_port = {}

        # Layer 3: Router Configuration
        self.router_dpids = {3} 

        self.port_to_own_mac = {
            1: "00:00:00:00:01:01", # MAC für Router-Interface an Port 1
            2: "00:00:00:00:01:02", # MAC für Router-Interface an Port 2
            3: "00:00:00:00:01:03"  # MAC für Router-Interface an Port 3
        }

        self.port_to_own_ip = {
            1: "10.0.1.1",    # IP für Router-Interface an Port 1
            2: "10.0.2.1",    # IP für Router-Interface an Port 2
            3: "192.168.1.1" # IP für Router-Interface an Port 3
        }

        self.arp_table = {}

        self.packet_buffer = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # ARP to Controller""
        """
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)
        """
        # Install default table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
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
    def _packet_in_handler(self, ev):
        msg = ev.msg

        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        dpid = datapath.id # Die DPID des Geräts, das das Paket gesendet hat


        # get all possible pkt types
        original_packet = packet.Packet(msg.data)
        ether_frame = original_packet.get_protocol(ethernet.ethernet)
        #arp_pkt = pkt.get_protocol(arp.arp)
        #ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not ether_frame:
            return

        # Ist das Gerät ein Router?
        is_router = dpid in self.router_dpids

        if is_router:
            self.logger.info(f"----------------------------------------------------------------------")
            if ether_frame.ethertype == ether.ETH_TYPE_ARP:
                self._handle_arp_for_router(datapath, original_packet, in_port)

            elif ether_frame.ethertype == ether.ETH_TYPE_IP:
                self._handle_ip_for_router(datapath, original_packet, in_port)
            else:
                pass
                #self.logger.info(f"Receive unknown packet {ether_frame.src} => {ether_frame.dst} (port: {in_port})")
        else:
            self._handle_switch_packet(datapath, msg.data, ether_frame, in_port)

    def _handle_arp_for_router(self, datapath, original_packet, in_port):

        arp_frame_in = original_packet.get_protocol(arp.arp)
        ether_frame_in = original_packet.get_protocol(ethernet.ethernet)
        target_ip = arp_frame_in.dst_ip

        if arp_frame_in.opcode != arp.ARP_REQUEST:
            self.logger.info(f"ROUTER RECEIVED: Received an ARP-Reply from {arp_frame_in.src_ip}")
            self.arp_table[arp_frame_in.src_ip] = ether_frame_in.src
            self.logger.info(f"ROUTER: Adjusted ARP-Table with [{arp_frame_in.src_ip} : {ether_frame_in.src}]")
            
            if arp_frame_in.src_ip in self.packet_buffer:
                received_ip_buffer = self.packet_buffer[arp_frame_in.src_ip]
            else:
                received_ip_buffer = []

            if received_ip_buffer == []:
                self.logger.info(f"ROUTER: There were no pending IP-Packets for the received information")
                return
            else:
                self.logger.info(f"ROUTER: There are pending IP-Packets for the received information of host: {arp_frame_in.src_ip}")
                for pending_packet in received_ip_buffer:

                    ip_frame = pending_packet.get_protocol(ipv4.ipv4)

                    src_ip = ip_frame.src
                    dst_ip = ip_frame.dst

                    out_port = None
                    router_outgoing_mac = None
                    router_outgoing_ip = None

                    for port_num, ip in self.port_to_own_ip.items(): 
                        if dst_ip.split(".")[0:3] == ip.split(".")[0:3]:
                            out_port = port_num
                            router_outgoing_mac = self.port_to_own_mac[port_num] # The router will be the new source
                            router_outgoing_ip = self.port_to_own_ip[port_num]
                            #self.logger.info(f"For IP {dst_ip} the port {out_port} was determined.")
                            break
                    try:
                        dst_mac = self.arp_table[dst_ip]        
                    except Exception as e:
                        self.logger.info(f"ROUTER: MAC address for {dst_ip} not in ARP table. Sending ARP-Request.")

                    if dst_mac:

                        out_packet = packet.Packet()

                        ether_frame = ethernet.ethernet(
                            src = router_outgoing_mac,
                            dst = dst_mac,
                            ethertype=ether.ETH_TYPE_IP
                        )

                        out_packet.add_protocol(ether_frame)
                        out_packet.add_protocol(ip_frame
                        )

                        if ip_frame.proto == inet.IPPROTO_ICMP:
                            icmp_frame = pending_packet.get_protocol(icmp.icmp)
                            new_pkt.add_protocol(icmp_frame)
                            
                        try:
                            out_packet.serialize()
                        except Exception as e:
                            self.logger.info(f"ERROR: While trying to serialize: {e}")

                        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                        packet_out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                                        in_port=in_port,
                                                                        actions=actions,
                                                                        data=out_packet.data
                                                                        )
                        datapath.send_msg(packet_out)
                        self.logger.info(f"ROUTER SENT: IP-Packet sent {ip_frame.src} -> {ip_frame.dst} : {ether_frame.dst} (Port: {out_port})")
                        received_ip_buffer.remove(pending_packet)
        else:
            self.logger.info(f"ROUTER RECEIVED: ARP-Request for IP {target_ip} from {arp_frame_in.src_ip}")

            out_port = in_port

            if out_port == None:
                self.logger.info(f"ROUTER WARNING: No local interface found for IP {target_ip}")
                return

            source_ip = arp_frame_in.src_ip
            source_mac = ether_frame_in.src
            requested_mac =  self.port_to_own_mac[out_port]
            requested_ip = self.port_to_own_ip[out_port]

            self.arp_table[source_ip] = source_mac

            arp_reply = arp.arp(
                opcode = arp.ARP_REPLY,
                src_mac = requested_mac, # The MAC of router that was requested from host
                src_ip = requested_ip, # The IP of router that was requested from host
                dst_mac = source_mac, # The MAC of the host that requested
                dst_ip = source_ip # The IP of the Host that requested
            )
            
            return_mac = source_mac # the MAC of the last hop

            ether_reply = ethernet.ethernet(
                src = requested_mac, # the router is currently sending
                dst = return_mac, # send it to the last hop
                ethertype = ether_frame_in.ethertype 
            )

            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(ether_reply)
            reply_pkt.add_protocol(arp_reply)
            reply_pkt.serialize()
            
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            packet_out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                            in_port=datapath.ofproto.OFPP_CONTROLLER,
                                                            actions=actions,
                                                            data=reply_pkt.data
                                                            )
            datapath.send_msg(packet_out)
            self.logger.info(f"ROUTER SENT: ARP-Reply for {source_ip, source_mac} -> {requested_mac}")

        return None

    def _handle_ip_for_router(self, datapath, original_packet, in_port):
        
        ether_frame = original_packet.get_protocol(ethernet.ethernet)
        ip_frame = original_packet.get_protocol(ipv4.ipv4)
        dpid = datapath.id

        src_ip = ip_frame.src
        dst_ip = ip_frame.dst
        
        self.logger.info(f"ROUTER RECEIVED: IP-Protocol from {src_ip} -> {dst_ip}")
        if ip_frame.ttl <= 1:
            self.logger.info("TTL expired, drop IP-Packet")
            return
        else:
            ip_frame.ttl -=  1
        
        out_port = None
        router_outgoing_mac = None
        router_outgoing_ip = None

        for port_num, ip in self.port_to_own_ip.items(): 
            #if src_ip.split(".")[0:3] == ip.split(".")[0:3]:
            #    if ip_frame.proto == inet.IPPROTO_ICMP:
            #        icmp_frame = original_packet.get_protocol(icmp.icmp)
            #        if icmp_frame.type == icmp.ICMP_ECHO_REQUEST or icmp_frame.type == icmp.ICMP_ECHO_REPLY:
            #            self.logger.info(f"There was a ping try to or from ext. This packet is dropped")
            #            return

            if dst_ip.split(".")[0:3] == ip.split(".")[0:3]:
                out_port = port_num
                router_outgoing_mac = self.port_to_own_mac[port_num] # The router will be the new source
                router_outgoing_ip = self.port_to_own_ip[port_num]
                #self.logger.info(f"For IP {dst_ip} the port {out_port} was determined.")
                break

        if out_port == None:
            self.logger.info(f"The Destination Network of the IP-Packet is not known to the Router")
            return
        
        dst_mac = False

        try:
            dst_mac = self.arp_table[dst_ip]        
        except Exception as e:
            self.logger.info(f"ROUTER: MAC address for {dst_ip} not in ARP table. Initialise ARP-Request.")

        if dst_mac:

            ether_frame.src = router_outgoing_mac
            ether_frame.dst = dst_mac

            try:
                original_packet.serialize()
            except Exception as e:
                self.logger.info(f"ERROR: While trying to serialize: {e}")

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            packet_out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                            in_port=in_port,
                                                            actions=actions,
                                                            data=original_packet.data
                                                            )
            datapath.send_msg(packet_out)
            self.logger.info(f"ROUTER SENT: IP-Packet sent {ip_frame.src} -> {ip_frame.dst} : {ether_frame.dst} (Port: {out_port})")
            
        else:
            
            #save packet in buffer for later reply
            if dst_ip not in self.packet_buffer:
                self.packet_buffer[dst_ip] = []
            
            self.packet_buffer[dst_ip].append(original_packet)
            self.logger.info(f"ROUTER: IP-Packet was buffered {src_ip} -> {dst_ip}")

            arp_request_payload = arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=router_outgoing_mac,
                src_ip=router_outgoing_ip,
                dst_mac='00:00:00:00:00:00',
                dst_ip=dst_ip
            )
            arp_request_ether_frame = ethernet.ethernet(
                src=router_outgoing_mac,
                dst='ff:ff:ff:ff:ff:ff',
                ethertype= ether.ETH_TYPE_ARP # ARP
            )

            arp_request_pkt = packet.Packet()
            arp_request_pkt.add_protocol(arp_request_ether_frame)
            arp_request_pkt.add_protocol(arp_request_payload)

            try:
                arp_request_pkt.serialize()
            except Exception as e:  
                self.logger.info(f"ERROR: While trying to serialize: {e}")


            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)] # Sende ARP-Anfrage über den Ausgangs-Port
            packet_out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=datapath.ofproto.OFPP_CONTROLLER, # Controller sendet das Paket
                actions=actions,
                data=arp_request_pkt.data
            )
            datapath.send_msg(packet_out)
            self.logger.info(f"ROUTER SENT: ARP-Request sent for {dst_ip} on port {out_port}")

    def _handle_switch_packet(self, datapath, data, eth_pkt, in_port):
        """
        Handles incoming packets at the switch.

        Args:
            datapath (ryu.controller.controller.Datapath): The datapath object representing the switch.
            data (bytes): The raw packet data.
            eth_pkt (ryu.lib.packet.ethernet.ethernet): The parsed Ethernet packet.
            in_port (int): The port the packet arrived on.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Initialize MAC to port mapping for this switch if not present
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        # Learn the source MAC address and the port it arrived on
        src_mac = eth_pkt.src
        self.mac_to_port[dpid][src_mac] = in_port

        dst_mac = eth_pkt.dst
        out_port = None

        # Check if we know the output port for the destination MAC
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            # Install a flow rule to forward future packets directly
            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)
        else:
            # Flood the packet on all ports if the destination is unknown
            out_port = ofproto.OFPP_FLOOD

        # Create the packet-out message to forward the current packet
        actions = [parser.OFPActionOutput(out_port)]
        packet_out = parser.OFPPacketOut(datapath=datapath,
                                           buffer_id=ofproto.OFP_NO_BUFFER,
                                           in_port=in_port,
                                           actions=actions,
                                           data=data)

        # Send the packet-out message to the switch
        datapath.send_msg(packet_out)