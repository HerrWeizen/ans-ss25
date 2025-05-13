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
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet, arp, ipv4, ether_types, packet # https://ryu.readthedocs.io/en/latest/library_packet.html

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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # ARP to Controller
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)

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
        data = msg.data
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id # Die DPID des Geräts, das das Paket gesendet hat


        # get all possible pkt types
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not eth_pkt:
            return

        # Ist das Gerät ein Router?
        is_router = dpid in self.router_dpids

        if is_router:
            #self.logger.info("Paket von Router DPID %s empfangen. Sender ist: %s", datapath.id, eth_pkt.src)
            # Hier Ihre ARP/IP-Logik für Router implementieren
            if arp_pkt:
                self._handle_arp_for_router(datapath, arp_pkt, eth_pkt, in_port)
                return

            if ip_pkt:
                self._handle_ip_for_router(datapath, ip_pkt, eth_pkt, in_port)
                return

        else:
            self.logger.info("Paket von Switch DPID %s empfangen. Sender ist: %s", dpid, eth_pkt.src)
            if arp_pkt:
                if arp_pkt.opcode == arp.ARP_REQUEST:
                    self.logger.info(f"Switch {datapath.id} got an ARP Request for IP: {arp_pkt.dst_ip} from {arp_pkt.src_ip}")
                elif arp_pkt.opcode == arp.ARP_REPLY:
                    self.logger.info(f"Switch {datapath.id} got an ARP Reply from IP: {arp_pkt.src_ip} for {arp_pkt.dst_ip}")
            self._handle_switch_packet(datapath, data, eth_pkt, in_port)

        
    def _handle_arp_for_router(self, datapath, arp_pkt_in, eth_pkt_in, in_port):

        if arp_pkt_in.opcode != arp.ARP_REQUEST:
            return
        
        target_ip = arp_pkt_in.dst_ip # der der gesucht wird?
        self.logger.info(f"ARP-Request for IP {target_ip} from {arp_pkt_in.src_ip}")

        #if target_ip not in self.port_to_own_ip.values():
        #    self.logger.info(f"ARP-Request not for our Router")
        #    return
        
        out_port = None
        for port, ip in self.port_to_own_ip.items():
            if target_ip.split(".")[0:3] == ip.split(".")[0:3]:
                out_port = port
                break

        if out_port == None:
            self.logger.info(f"No local interface found for IP {target_ip}")
            return

        source_ip = arp_pkt_in.src_ip
        source_mac = eth_pkt_in.src
        requested_mac =  self.port_to_own_mac[out_port]
        requested_ip = self.port_to_own_ip[out_port]

        self.arp_table[source_ip] = source_mac
        self.logger.info(f"ARP-Table: The entry for IP {source_ip} has been set for MAC {source_mac}")
        arp_reply = arp.arp(
            opcode = arp.ARP_REPLY,
            src_mac = requested_mac, # The MAC of router that was requested from host
            src_ip = requested_ip, # The IP of router that was requested from host
            dst_mac = source_mac, # The MAC of the host that requested
            dst_ip = source_ip # The IP of the Host that requested
        )
        
        
        return_mac = source_mac # the MAC of the last hop

        eth_reply = ethernet.ethernet(
            src = requested_mac, # the router is currently sending
            dst = return_mac, # send it to the last hop
            ethertype = eth_pkt_in.ethertype 
        )


        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(eth_reply)
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
        self.logger.info(f"ARP-Reply for {source_ip} -> {requested_mac}")

        return None
    
    def _handle_ip_for_router(self, datapath, ip_pkt_in, eth_pkt_in, in_port):
        
        src_ip = ip_pkt_in.src
        dst_ip = ip_pkt_in.dst
        
        if ip_pkt_in.ttl <= 1:
            self.logger.info("TTL expired, drop IP-Packet")
            return
        else:
            new_ttl = ip_pkt_in.ttl - 1
        
        out_port = None
        out_src_mac = None
        out_src_ip = None
        for port, ip in self.port_to_own_ip.items():
            if dst_ip.split(".")[0:3] == ip.split(".")[0:3]:
                out_port = port
                out_src_ip = ip
                out_src_mac = self.port_to_own_mac[port] # The router will be the new source
                #self.logger.info(f"For IP {dst_ip} the port {out_port} was determined.")
                break

        
        if out_port == None:
            self.logger.info(f"The Destination Network of the IP-Packet is not known to the Router")
            return
        
        
        try:
            dst_mac = self.arp_table[dst_ip]
            ip_pkt_out = ipv4.ipv4(
                version = ip_pkt_in.version,
                tos=ip_pkt_in.tos,
                flags = ip_pkt_in.flags,
                ttl= new_ttl,
                proto= ip_pkt_in.proto,
                src = ip_pkt_in.src,
                dst = ip_pkt_in.dst
            )
            ip_pkt_out.ttl = new_ttl

            eth_pkt_out = ethernet.ethernet(
                src = out_src_mac,
                dst = dst_mac,
                ethertype = eth_pkt_in.ethertype
            )

            out_pkt = packet.Packet()
            out_pkt.add_protocol(eth_pkt_out)
            out_pkt.add_protocol(ip_pkt_out)
            try:
                out_pkt.serialize()
                #self.logger.info(f"Serialized ARP packet: {out_pkt.data}")
            except:
                self.logger.info(f"The Serialization is also in IP-Send fucked")
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            packet_out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                            in_port=in_port,
                                                            actions=actions,
                                                            data=out_pkt.data
                                                            )
            datapath.send_msg(packet_out)
            self.logger.info(f"IP-Packet routed from {ip_pkt_in.src} -> {ip_pkt_in.dst}")
        
        except KeyError:

            self.logger.info(f"MAC address for {dst_ip} not in ARP table. Sending ARP-Request.")
            # Generiere ARP-Anfrage
            arp_request = arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=out_src_mac,
                src_ip=out_src_ip,
                dst_mac='ff:ff:ff:ff:ff:ff',
                dst_ip=dst_ip
            )
            eth_arp = ethernet.ethernet(
                src=out_src_mac,
                dst='ff:ff:ff:ff:ff:ff',
                ethertype= 0x0806 # ARP
            )
            arp_request_pkt = packet.Packet()
            arp_request_pkt.add_protocol(eth_arp)
            arp_request_pkt.add_protocol(arp_request)
            try:
                arp_request_pkt.serialize()
                #self.logger.info(f"Serialized ARP packet: {arp_request_pkt.data}")
            except:
                self.logger.info(f"The Serialization was fucked")
                return

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)] # Sende ARP-Anfrage über den Ausgangs-Port
            packet_out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=datapath.ofproto.OFPP_CONTROLLER, # Controller sendet das Paket
                actions=actions,
                data=arp_request_pkt.data
            )
            datapath.send_msg(packet_out)
            self.logger.info(f"ARP-Request sent for {dst_ip} on port {out_port}")

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
            self.logger.info(f"Switch is flooding")
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