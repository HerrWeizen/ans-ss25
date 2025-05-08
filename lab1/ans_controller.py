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

    from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp
from ryu.ofproto import ether as ether_types  # Import für EtherTypes (ETH_TYPE_ARP, ETH_TYPE_IP)
from ryu.ofproto import inet  # Import für IP Protokollnummern (IPPROTO_ICMP)

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        
        # Layer 2: MAC Learning Table
        self.mac_to_port = {}

        # Layer 3: Router Configuration
        self.router_dpids = {2,3} # Beispiel DPID für einen Router

        # Diese Dictionaries definieren die MAC- und IP-Adressen der Router-Interfaces
        # Schlüssel: Portnummer am Router-Switch
        # Wert: MAC- oder IP-Adresse als String
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

        # ARP-Cache für den Router: Speichert IP -> MAC Mappings
        # Wird durch eingehende ARP-Pakete gefüllt
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

            self._handle_switch_packet(datapath, data, eth_pkt, in_port)

        

    def _handle_switch_packet(self, datapath, data, eth_pkt, in_port):
        """
        Handles incoming packets at the switch.

        Args:
            datapath (ryu.controller.controller.Datapath): The datapath object representing the switch.
            data (bytes): The raw packet data.
            eth_pkt (ryu.lib.packet.ethernet.ethernet): The parsed Ethernet packet.
            in_port (int): The port the packet arrived on.
        """
        self.logger.info("Switch Logic is handling the packet.")
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
