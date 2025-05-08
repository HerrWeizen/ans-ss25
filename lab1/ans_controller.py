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
        self.router_dpids = {4}

        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }

        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

        self.arp_cache = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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
            self.logger.info("Paket von Router DPID %s empfangen", dpid)
            # Hier Ihre ARP/IP-Logik für Router implementieren
            if arp_pkt:
                self._handle_arp_for_router(datapath, arp_pkt, eth_pkt, in_port)
                return

            if ip_pkt:
                self._handle_ip_for_router(datapath, ip_pkt, eth_pkt, in_port)
                return

        else:
            self.logger.info("Paket von Switch DPID %s empfangen", dpid)
            # Hier Ihre Switch-Logik implementieren (z.B. MAC Learning)
            self._handle_switch_packet(datapath, data, eth_pkt, in_port)

    def handle_arp(self, datapath, in_port, eth_pkt, arp_pkt):
        if not arp_pkt:
            return

        if arp_pkt.opcode == arp.ARP_REQUEST:
            self.handle_arp_request(datapath, in_port, eth_pkt, arp_pkt)
        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.handle_arp_reply(arp_pkt)

    def handle_arp_request(self, datapath, in_port, eth_pkt, arp_pkt):
        target_ip = arp_pkt.dst_ip

        # Only respond to gateway IPs
        if target_ip not in self.GATEWAY_IPS:
            self.logger.debug(f"Ignoring ARP request for non-gateway IP: {target_ip}")
            return

        # Verify the request is for this router's interface
        if in_port not in self.port_to_own_ip:
            self.logger.error(f"Received ARP on unconfigured port {in_port}")
            return

        if target_ip != self.port_to_own_ip[in_port]:
            self.logger.warning(f"Port {in_port} not responsible for {target_ip}")
            return

        # Build ARP reply
        arp_reply = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=self.port_to_own_mac[in_port],
            src_ip=target_ip,
            dst_mac=arp_pkt.src_mac,
            dst_ip=arp_pkt.src_ip
        )

        eth_reply = ethernet.ethernet(
            ethertype=eth_pkt.ethertype,
            dst=eth_pkt.src,
            src=self.port_to_own_mac[in_port]
        )

        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(eth_reply)
        reply_pkt.add_protocol(arp_reply)
        reply_pkt.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(port=in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=reply_pkt.data
        )
        datapath.send_msg(out)
        self.logger.info(f"Sent ARP reply for {target_ip} via port {in_port}")

    def handle_arp_reply(self, arp_pkt):
        self.arp_cache[arp_pkt.src_ip] = arp_pkt.src_mac
        self.logger.info(f"Updated ARP cache: {arp_pkt.src_ip} -> {arp_pkt.src_mac}")

    def handle_ip(self, datapath, in_port, eth_pkt, ip_pkt):
        self.logger.info(f"Router IP Logic is handling the packet from port {in_port}")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src

        self.logger.info(f"Router received IP packet from {src_ip} to {dst_ip}")

        # Check which router port the packet arrived on
        incoming_subnet = None
        for port, ip in self.port_to_own_ip.items():
            if ip.split('.')[0:3] == dst_ip.split('.')[0:3]:  # Check /24 subnet
                incoming_subnet = port
                break

        # Case 1: Destination IP is in one of the router's subnets
        if incoming_subnet:
            # Forward to the correct port (e.g., 10.0.1.2 -> Port 1)
            out_port = incoming_subnet
            actions = [parser.OFPActionOutput(out_port)]

        # Case 2: Destination IP is external (e.g., Internet)
        else:
            # Default route (e.g., send to Port 3 as gateway)
            out_port = 3  # connects to internet
            actions = [parser.OFPActionOutput(out_port)]

        # Rewrite MAC addresses (Router replaces src/dst MAC)
        dst_mac = self.get_dst_mac_for_ip(dst_ip)
        if dst_mac is None:
            self.logger.error(f"No MAC found for IP {dst_ip}, dropping packet")
            return

        new_eth = ethernet.ethernet(
            src=self.port_to_own_mac[out_port],  # Router's MAC for the out_port
            dst=dst_mac,
            ethertype=eth_pkt.ethertype
        )

        # Rebuild the packet with new Ethernet header
        new_pkt = packet.Packet()
        new_pkt.add_protocol(new_eth)
        new_pkt.add_protocol(ip_pkt)  # Keep original IP packet
        new_pkt.serialize()

        # Send the packet out
        self._send_packet(datapath, out_port, new_pkt)

        # Install a flow to avoid future packet-ins
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=dst_ip
        )
        self.add_flow(datapath, 2, match, actions)
        
    def get_dst_mac_for_ip(self, ip):
        if ip in self.arp_cache:
            return self.arp_cache[ip]
        else:
            # Send ARP request.  Important:  Prevent infinite loop.
            self.logger.warning(f"No ARP entry for {ip}, sending ARP request")
            return self.send_arp_request(self.datapath, ip) # Removed datapath from parameter list.


    def _send_packet(self, datapath, out_port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
        
    def send_arp_request(self, datapath, target_ip):
        # Find the appropriate outgoing port and source IP for the target IP.
        out_port = None
        src_ip = None
        for port, ip in self.port_to_own_ip.items():
            if target_ip.split('.')[0:3] == ip.split('.')[0:3]:
                out_port = port
                src_ip = ip
                break

        if out_port is None or src_ip is None:
            self.logger.error(f"No suitable interface found to send ARP request for {target_ip}")
            return None  # Important:  Return None, don't send packet.

        e = ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',  # Broadcast
            src=self.port_to_own_mac[out_port],
            ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=self.port_to_own_mac[out_port],
            src_ip=src_ip,
            dst_mac='00:00:00:00:00:00',  # Unused in request
            dst_ip=target_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        self._send_packet(datapath, out_port, p)  # Use the _send_packet helper
        self.logger.info(f"Sent ARP request for {target_ip} on port {out_port}")
        return None # return None, because the mac address is unknown.

    def _handle_switch_packet(self, datapath, data, eth_pkt, in_port):
        
        self.logger.info(f"Switch Logic is handling the packet.")
        ofproto = datapath.ofproto
    
        #pkt = packet.Packet(msg.data) # Removed pkt, used eth_pkt
        # extract ethernet layer form parsed object
        #eth = pkt.get_protocol(ethernet.ethernet) # Removed, using parameter.

        # ethernet destination and source as MAC-addresses (strings)
        dst_MAC = eth_pkt.dst
        src_MAC = eth_pkt.src

        # get unique id from the switch
        dpid = datapath.id

        # add a new table for the dpid if not present (i hope so)
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        
        # create the MAC - Port entry#
        if src_MAC not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src_MAC] = in_port

        # look if the destination is present in the mac - port table for the switch, if not flood all ports
        if dst_MAC in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_MAC] # port to send the message to
            # tell the stupid ass switch what the fuck to do (install flow):
            match = datapath.ofproto_parser.OFPMatch(eth_dst=dst_MAC) # a filter: when in ethernet the dst_MAC is found ... 
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)] # ... send in to this port
            self.add_flow(datapath, 1, match, actions) # give the above rule of match / action to the switch
        else:
            out_port = ofproto.OFPP_FLOOD # flood all ports

        ## Okay, also n die flowregel wurde gesetzt, jetzt muss man das scheiß ding auch noch selbst weiter leiten weil alles doof
        ##response = self.mac_to_port[dpid][dst_MAC]
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # Was abgeschickt werden soll
        forward = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, 
                                                       buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                       in_port=in_port, 
                                                       actions=actions,
                                                       data=data)

        # Datapath sagen, schick den scheiß
        datapath.send_msg(forward)
