#+ß
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

import os
import subprocess
import time

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

from topo import Fattree
import time

class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """


    def __init__(self, ft_topo):

        Topo.__init__(self)
        self.nodeMap = {}
        self.mynodes = set()
        self.myedges = set()

        # switch = (Node, IP)
        i = 1
        for switch in ft_topo.switches["all"]:
            dpid = self.create_dpid(i)
            self.addSwitch(switch[0].id, ip=switch[1], dpid=dpid)
            self.nodeMap[switch[0]] = switch[0].id
            self.mynodes.add(switch)
            i+=1

        # server = (Node, IP)
        for server in ft_topo.servers:
            self.addHost(server[0].id, ip=server[1])
            self.nodeMap[server[0]] = server[0].id
            self.mynodes.add(server)
            i+=1

        for edge in ft_topo.edges:
            node1 = self.nodeMap[edge.lnode]
            node2 = self.nodeMap[edge.rnode]
            self.addLink(node1, node2, cls=TCLink, bw=15, delay="5ms")
            print(f"AddedLink {node1} -> {node2}")
            self.myedges.add(edge)

    def create_dpid(self, n):
        return format(n, '016x')

def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)

    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()

def main():
    ft_topo = Fattree(4)
    run(ft_topo)
    
if __name__ == '__main__':
    main()
