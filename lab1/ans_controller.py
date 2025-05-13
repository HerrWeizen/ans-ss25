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
            
            if ether_frame.ethertype == ether.ETH_TYPE_ARP:
                self._handle_arp_for_router(datapath, original_packet, in_port)

            elif ether_frame.ethertype == ether.ETH_TYPE_IP:
                self._handle_ip_for_router(datapath, original_packet, in_port)
            else:
                self.logger.info(f"Receive unknown packet {ether_frame.src} => {ether_frame.dst} (port: {in_port})")


            #if arp_pkt:
            #    self._handle_arp_for_router(datapath, arp_pkt, eth_pkt, in_port)
            #    return

            #if ip_pkt:
            #    self._handle_ip_for_router(datapath, ip_pkt, eth_pkt, in_port)
            #    return

        else:
            """
            self.logger.info("Paket von Switch DPID %s empfangen. Sender ist: %s", dpid, eth_pkt.src)
            if arp_pkt:
                if arp_pkt.opcode == arp.ARP_REQUEST:
                    self.logger.info(f"Switch {datapath.id} got an ARP Request for IP: {arp_pkt.dst_ip} from {arp_pkt.src_ip}")
                elif arp_pkt.opcode == arp.ARP_REPLY:
                    self.logger.info(f"Switch {datapath.id} got an ARP Reply from IP: {arp_pkt.src_ip} for {arp_pkt.dst_ip}")
            """
            self._handle_switch_packet(datapath, msg.data, ether_frame, in_port)

"""
    def _handle_arp_for_router(self, datapath, original_packet, in_port):

        arp_frame_in = original_packet.get_protocol(arp.arp)
        ether_frame_in = original_packet.get_protocol(ethernet.ethernet)

        if arp_frame_in.opcode != arp.ARP_REQUEST:
            self.logger.info(f"ROUTER RECEIVED: Received an ARP-Reply from {arp_frame_in.src_ip}")
            self.arp_table[arp_frame_in.src_ip] = ether_frame_in.src
            self.logger.info(f"ROUTER: Adjusted ARP-Table with [{arp_frame_in.src_ip} : {ether_frame_in.src}]")
        
        target_ip = arp_frame_in.dst_ip # der der gesucht wird?
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
"""

    def _handle_arp_for_router(self, datapath, original_packet, in_port):
            arp_frame_in = original_packet.get_protocol(arp.arp)
            ether_frame_in = original_packet.get_protocol(ethernet.ethernet)
            dpid = datapath.id

            if arp_frame_in.opcode == arp.ARP_REPLY:
                learned_ip = arp_frame_in.src_ip
                learned_mac = arp_frame_in.src_mac # Die MAC-Adresse aus dem ARP-Payload ist die gesuchte
                
                self.logger.info(f"ROUTER DPID {dpid} RECEIVED: ARP-Reply for {learned_ip} (MAC: {learned_mac}) from L2 src {ether_frame_in.src}")
                
                # Nur in ARP-Tabelle eintragen, wenn die MAC nicht eine Broadcast/Multicast-Adresse ist
                if not (int(learned_mac.split(':')[0], 16) & 1): # Check for multicast/broadcast bit
                    self.arp_table[learned_ip] = learned_mac
                    self.logger.info(f"ROUTER DPID {dpid}: Updated ARP-Table with [{learned_ip} : {learned_mac}]")

                    # Prüfe Paketpuffer auf Pakete, die auf diese ARP-Auflösung warten
                    buffer_key = (dpid, learned_ip)
                    if buffer_key in self.packet_buffer:
                        buffered_items = self.packet_buffer.pop(buffer_key) # Hole und entferne List
                        self.logger.info(f"ROUTER DPID {dpid}: Found {len(buffered_items)} packet(s) in buffer for {learned_ip}. Sending now.")
                        for item_out_port, item_router_src_mac, item_ip_frame_to_send, item_payload_protocols in buffered_items:
                            
                            pkt_to_resend = packet.Packet()
                            pkt_to_resend.add_protocol(ethernet.ethernet(
                                dst=learned_mac, # Die neu gelernte MAC-Adresse
                                src=item_router_src_mac, # Die MAC-Adresse des Router-Ausgangsports
                                ethertype=ether.ETH_TYPE_IP
                            ))
                            pkt_to_resend.add_protocol(item_ip_frame_to_send) # Der IP-Frame mit bereits dekrementiertem TTL
                            for p_payload in item_payload_protocols: # Hänge den ursprünglichen Payload an
                                pkt_to_resend.add_protocol(p_payload)
                            pkt_to_resend.serialize()

                            actions_resend = [datapath.ofproto_parser.OFPActionOutput(item_out_port)]
                            out_resend = datapath.ofproto_parser.OFPPacketOut(
                                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions_resend, data=pkt_to_resend.data)
                            datapath.send_msg(out_resend)
                            self.logger.info(f"ROUTER DPID {dpid}: Sent buffered IP packet to {item_ip_frame_to_send.dst} (MAC: {learned_mac}) via port {item_out_port}")
                else:
                    self.logger.warning(f"ROUTER DPID {dpid}: Received ARP reply from {learned_ip} with broadcast/multicast MAC {learned_mac}. ARP entry not created.")
                return # ARP Reply verarbeitet

            elif arp_frame_in.opcode == arp.ARP_REQUEST:
                # Bestehende Logik für die Beantwortung von ARP-Anfragen für die eigene(n) IP(s) des Routers
                target_ip = arp_frame_in.dst_ip # Die IP, für die die MAC gesucht wird
                self.logger.info(f"ROUTER DPID {dpid} RECEIVED: ARP-Request for IP {target_ip} from {arp_frame_in.src_ip} on port {in_port}")

                # Prüfen, ob die Anfrage für eine der IPs des Routers auf diesem Port ist
                if self.port_to_own_ip.get(in_port) == target_ip:
                    source_ip_of_requestor = arp_frame_in.src_ip
                    source_mac_of_requestor = ether_frame_in.src # MAC des Anfragenden Ethernet-Frames

                    router_reply_mac = self.port_to_own_mac[in_port]
                    router_reply_ip = self.port_to_own_ip[in_port]

                    # Lerne die MAC des Anfragenden, falls noch nicht bekannt
                    if source_ip_of_requestor not in self.arp_table or self.arp_table[source_ip_of_requestor] != source_mac_of_requestor :
                        if not (int(source_mac_of_requestor.split(':')[0], 16) & 1):
                            self.arp_table[source_ip_of_requestor] = source_mac_of_requestor
                            self.logger.info(f"ROUTER DPID {dpid}: Learned/Updated ARP entry from ARP_REQUEST: [{source_ip_of_requestor} : {source_mac_of_requestor}]")


                    arp_reply_payload = arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=router_reply_mac, 
                        src_ip=router_reply_ip, 
                        dst_mac=source_mac_of_requestor, 
                        dst_ip=source_ip_of_requestor 
                    )
                    
                    ether_reply_frame = ethernet.ethernet(
                        src=router_reply_mac, 
                        dst=source_mac_of_requestor, 
                        ethertype=ether.ETH_TYPE_ARP 
                    )

                    reply_pkt = packet.Packet()
                    reply_pkt.add_protocol(ether_reply_frame)
                    reply_pkt.add_protocol(arp_reply_payload)
                    reply_pkt.serialize()
                    
                    actions_reply = [datapath.ofproto_parser.OFPActionOutput(in_port)] # Sende auf dem Port zurück, auf dem die Anfrage kam
                    out_reply = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions_reply, data=reply_pkt.data)
                    datapath.send_msg(out_reply)
                    self.logger.info(f"ROUTER DPID {dpid} SENT: ARP-Reply for our IP {router_reply_ip} to {source_ip_of_requestor} ({source_mac_of_requestor}) via port {in_port}")
                else:
            
                    self.logger.info(f"ROUTER DPID {dpid}: Received ARP Request for external IP {target_ip}. Ignoring.")
    """
    def _handle_ip_for_router(self, datapath, original_packet, in_port):
        
        ether_frame = original_packet.get_protocol(ethernet.ethernet)
        ip_frame = original_packet.get_protocol(ipv4.ipv4)


        src_ip = ip_frame.src
        dst_ip = ip_frame.dst
        
        if ip_frame.ttl <= 1:
            self.logger.info("TTL expired, drop IP-Packet")
            return
        else:
            ip_frame.ttl -=  1
        
        out_port = None
        router_outgoing_mac = None
        router_outgoing_ip = None

        for port_num, ip in self.port_to_own_ip.items():
            

            if src_ip.split(".")[0:3] == ip.split(".")[0:3]:
                if ip_frame.proto == inet.IPPROTO_ICMP:
                    icmp_frame = original_packet.get_protocol(icmp.icmp)
                    if icmp_frame.type == icmp.ICMP_ECHO_REQUEST or icmp_frame.type == icmp.ICMP_ECHO_REPLY:
                        self.logger.info(f"There was a ping try to or from ext. This packet is dropped")
                        return


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
            self.logger.info(f"ROUTER: MAC address for {dst_ip} not in ARP table. Sending ARP-Request.")

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
            self.logger.info(f"ROUTER: IP-Packet sent {ip_frame.src} -> {ip_frame.dst}")
            
        else:

            
            # Generiere ARP-Anfrage
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

    """
    def _handle_ip_for_router(self, datapath, original_packet, in_port):
        ether_frame = original_packet.get_protocol(ethernet.ethernet)
        ip_frame = original_packet.get_protocol(ipv4.ipv4)
        dpid = datapath.id

        # A. Prüfen, ob das Paket für den Router selbst bestimmt ist (z.B. Ping an Router-IP)
        for port_num_check, router_ip_check in self.port_to_own_ip.items():
            if ip_frame.dst == router_ip_check:
                if ip_frame.proto == inet.IPPROTO_ICMP:
                    icmp_pkt = original_packet.get_protocol(icmp.icmp)
                    if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                        self.logger.info(f"ROUTER DPID {dpid}: IP packet for router's own IP {ip_frame.dst} (ICMP Echo Request). Handling.")
                        self._send_icmp_echo_reply(datapath, original_packet, in_port)
                        return
                self.logger.info(f"ROUTER DPID {dpid}: IP packet for router's own IP {ip_frame.dst} (Proto: {ip_frame.proto}). Not ICMP Echo, dropping for now.")
                return

        # B. Routing-Entscheidung treffen
        out_port = None
        router_outgoing_mac = None # MAC der Router-Schnittstelle für das Senden von ARP/Daten
        router_outgoing_ip = None  # IP der Router-Schnittstelle für das Senden von ARP

        for port_num, r_ip_subnet_check in self.port_to_own_ip.items():
            # Einfaches /24 Subnetz-Matching. Annahme: Jedes Port ist in einem eigenen /24 Netz.
            # Verhindert auch das Routen auf dasselbe Interface bei Subnetz-Match (einfache Schleifenvermeidung)
            if ip_frame.dst.split('.')[0:3] == r_ip_subnet_check.split('.')[0:3] and port_num != in_port:
                # Sicherstellen, dass die Ziel-IP nicht die Router-IP auf dem potenziellen Ausgangsport ist
                if ip_frame.dst == r_ip_subnet_check:
                    self.logger.warning(f"ROUTER DPID {dpid}: Destination {ip_frame.dst} is router's own IP on out_port {port_num}. Should be handled by 'packet for router itself' logic.")
                    return # Bereits oben behandelt oder Fehlerfall

                out_port = port_num
                router_outgoing_mac = self.port_to_own_mac[port_num]
                router_outgoing_ip = self.port_to_own_ip[port_num]
                break
        
        if out_port is None:
            self.logger.info(f"ROUTER DPID {dpid}: No route for {ip_frame.dst} from {ip_frame.src}. Dropping.")
            self._send_icmp_error(datapath, original_packet, in_port, icmp.ICMP_DEST_UNREACH, icmp.ICMP_NET_UNREACH_CODE)
            return

        # C. TTL-Prüfung und Dekrementierung (vor dem Senden oder Puffern)
        if ip_frame.ttl <= 1:
            self.logger.info(f"ROUTER DPID {dpid}: TTL expired for packet to {ip_frame.dst}. Dropping.")
            self._send_icmp_error(datapath, original_packet, in_port, icmp.ICMP_TIME_EXCEEDED, icmp.ICMP_TTL_EXCEEDED_CODE)
            return

        # Erstelle eine Kopie des IP-Frames für die Weiterleitung mit dekrementiertem TTL
        # (original_packet.protocols enthält die Protokolle in der Reihenfolge, wie sie geparsed wurden)
        payload_protocols = []
        found_ip_layer = False
        for p in original_packet.protocols:
            if p is ip_frame:
                found_ip_layer = True
                continue
            if found_ip_layer:
                payload_protocols.append(p)

        ip_frame_to_forward = ipv4.ipv4(
            version=ip_frame.version, header_length=ip_frame.header_length, tos=ip_frame.tos,
            total_length=ip_frame.total_length, identification=ip_frame.identification,
            flags=ip_frame.flags, offset=ip_frame.offset, ttl=ip_frame.ttl - 1,
            proto=ip_frame.proto, csum=0, src=ip_frame.src, dst=ip_frame.dst, option=ip_frame.option
        )

        # D. MAC-Adresse des Ziels holen oder ARP auslösen
        dst_mac_for_packet = self.arp_table.get(ip_frame.dst)

        if dst_mac_for_packet:
            # MAC bekannt, Paket direkt senden
            self.logger.info(f"ROUTER DPID {dpid}: MAC for {ip_frame.dst} found: {dst_mac_for_packet}. Forwarding IP packet.")
            
            pkt_to_send = packet.Packet()
            pkt_to_send.add_protocol(ethernet.ethernet(dst=dst_mac_for_packet, src=router_outgoing_mac, ethertype=ether.ETH_TYPE_IP))
            pkt_to_send.add_protocol(ip_frame_to_forward) # Mit dekrementiertem TTL
            for p_payload in payload_protocols: # Original-Payload anhängen
                pkt_to_send.add_protocol(p_payload)
            pkt_to_send.serialize()

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            out_msg = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt_to_send.data)
            datapath.send_msg(out_msg)
            self.logger.info(f"ROUTER DPID {dpid}: IP-Packet sent {ip_frame_to_forward.src} -> {ip_frame_to_forward.dst} via port {out_port}")
        else:
            # MAC unbekannt, Paket puffern und ARP-Anfrage senden
            self.logger.info(f"ROUTER DPID {dpid}: MAC for {ip_frame.dst} not in ARP table. Buffering packet and sending ARP-Request.")
            
            buffer_key = (dpid, ip_frame.dst)
            if buffer_key not in self.packet_buffer:
                self.packet_buffer[buffer_key] = []
            
            # Begrenze die Anzahl der gepufferten Pakete pro IP, um Speicherüberlauf zu vermeiden
            if len(self.packet_buffer[buffer_key]) < 5:
                 # Speichere: (out_port, router_eigener_src_mac, ip_frame_mit_dekrementiertem_ttl, payload_protokolle)
                self.packet_buffer[buffer_key].append(
                    (out_port, router_outgoing_mac, ip_frame_to_forward, payload_protocols)
                )
                self.logger.info(f"ROUTER DPID {dpid}: Packet for {ip_frame.dst} buffered. Buffer size for this IP: {len(self.packet_buffer[buffer_key])}")
            else:
                self.logger.warning(f"ROUTER DPID {dpid}: Buffer for {ip_frame.dst} full. Dropping new packet.")
                # Optional: ICMP Host Unreachable senden
                self._send_icmp_error(datapath, original_packet, in_port, icmp.ICMP_DEST_UNREACH, icmp.ICMP_HOST_UNREACH_CODE) # Code für "Communication Administratively Prohibited" wäre hier vielleicht passender
                return


            # Generiere ARP-Anfrage (wie in Ihrem Code)
            arp_request_payload = arp.arp(
                opcode=arp.ARP_REQUEST, src_mac=router_outgoing_mac, src_ip=router_outgoing_ip,
                dst_mac='00:00:00:00:00:00', dst_ip=ip_frame.dst)
            arp_request_ether_frame = ethernet.ethernet(
                src=router_outgoing_mac, dst='ff:ff:ff:ff:ff:ff', ethertype=ether.ETH_TYPE_ARP)
            
            arp_request_pkt = packet.Packet()
            arp_request_pkt.add_protocol(arp_request_ether_frame)
            arp_request_pkt.add_protocol(arp_request_payload)
            arp_request_pkt.serialize()

            actions_arp = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            out_arp = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions_arp, data=arp_request_pkt.data)
            datapath.send_msg(out_arp)
            self.logger.info(f"ROUTER DPID {dpid}: ARP-Request sent for {ip_frame.dst} via port {out_port}")

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