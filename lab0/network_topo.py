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

#!/usr/bin/python

from mininet.topo import Topo
from mininet.node import OVSBridge
from mininet.link import TCLink

class BridgeTopo(Topo):
    "Creat a bridge-like customized network topology according to Figure 1 in the lab0 description."

    def __init__(self):

        Topo.__init__(self)
        
        hosts = {}
        for i in range(1,5):
            hosts[f"h{i}"] = self.addHost(name=f"h{i}", ip=f"10.0.0.{i}/24")
        
        switches = {}
        for i in range(1,3):
            switches[f"s{i}"] = self.addSwitch(name=f"s{i}", cls=OVSBridge)
        
        #host-switch links
        self.addLink(hosts["h1"], switches["s1"], cls=TCLink, bw=15, delay="10ms")
        self.addLink(hosts["h2"], switches["s1"], cls=TCLink, bw=15, delay="10ms")        
        self.addLink(hosts["h3"], switches["s2"], cls=TCLink, bw=15, delay="10ms")        
        self.addLink(hosts["h4"], switches["s2"], cls=TCLink, bw=15, delay="10ms")
        
        #switch link
        self.addLink(switches["s1"], switches["s2"], cls=TCLink, bw=20, delay="45ms")
        
topos = {'bridge': (lambda: BridgeTopo())}
