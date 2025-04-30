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
from ryu.lib.packet import ethernet, arp, packet # https://ryu.readthedocs.io/en/latest/library_packet.html


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] # Unterstütze OpenFlow 1.3 protokoll für switch / controller communication

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Tabelle für MAC/Ports
        self.mac_to_port = {}
        

    # Wird aufgerufen wenn sich die switch nach dem Verbindungsaufbau beim Controller meldet 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) # This decorater tells RYU when to perform the decorated function
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath # ev.msg is smth that represents a packet_in data structure, ) ev.msg = message -> message.datapath = 
        ofproto = datapath.ofproto  # Stuff from OF negotiation
        parser = datapath.ofproto_parser # parser kann nachrichten erzeugen

        # Initial flow entry for matching misses<
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event, Happens only when there is no flow-rule
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev): # wtf is ev?
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        # parse raw packet into a structure object - .data extracts the raw data from the msg - contains all protocol parts
        pkt = packet.Packet(msg.data)

        # extract ethernet layer form parsed object
        eth = pkt.get_protocol(ethernet.ethernet) 

        # ethernet destination and source as MAC-addresses (strings)
        dst_MAC = eth.dst
        src_MAC = eth.src

        # get unique id from the switch
        dpid = datapath.id

        # add a new table for the dpid if not present (i hope so)
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        
        # create the MAC - Port entry
        self.mac_to_port[dpid][src_MAC] = msg.in_port

        # look if the destination is present in the mac - port table for the switch, if not flood all ports
        if dst_MAC in self.mac_to_port[dpid]:
            response = self.mac_to_port[dpid][dst_MAC] # port to send the message to

            # tell the stupid ass switch what the fuck to do (install flow):
            match = datapath.ofproto_parser.OFPMatch(eth_dst=dst_MAC) # a filter: when in ethernet the dst_MAC is found ... 
            actions = [datapath.ofproto_parser.OFPActionOutput(response)] # ... send in to this port
            self.add_flow(datapath, 1, match, actions) # give the above rule of match / action to the switch
        else:
            response = ofproto.OFPP_FLOOD # flood all ports

        ## Okay, also n die flowregel wurde gesetzt, jetzt muss man das scheiß ding auch noch selbst weiter leiten weil alles doof
        response = self.mac_to_port[dpid][dst_MAC]
        actions = [datapath.ofproto_parser.OFPActionOutput(response)]

        # Was abgeschickt werden soll
        forward = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                       in_port=msg.in_port, actions=actions,
                                                       data=msg.data)
        
        # Datapath sagen, schick den scheiß
        datapath.send_msg(forward)
