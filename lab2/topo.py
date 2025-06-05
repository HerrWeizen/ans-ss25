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

# Class for an edge in the graph
class Edge:
	def __init__(self):
		self.lnode = None
		self.rnode = None
	
	def remove(self):
		self.lnode.edges.remove(self)
		self.rnode.edges.remove(self)
		self.lnode = None
		self.rnode = None

# Class for a node in the graph
class Node:
	def __init__(self, id, type):
		self.edges = []
		self.id = id
		self.type = type

	# Add an edge connected to another node
	def add_edge(self, node):
		edge = Edge()
		edge.lnode = self
		edge.rnode = node
		self.edges.append(edge)
		node.edges.append(edge)
		return edge

	# Remove an edge from the node
	def remove_edge(self, edge):
		self.edges.remove(edge)

	# Decide if another node is a neighbor
	def is_neighbor(self, node):
		for edge in self.edges:
			if edge.lnode == node or edge.rnode == node:
				return True
		return False


class Fattree:

	def __init__(self, num_ports):
		self.servers = []
		self.switches = []
		self.core_switches = []
		self.aggregation_switches = [[] for _ in range(num_ports)]
		self.edge_switches = [[] for _ in range(num_ports)]
		self.generate(num_ports)

	def generate(self, num_ports):
	
		#switches
		#core k/2 * k/2
		for i in range(num_ports//2):
		    for j in range(num_ports//2):
		        node = Node(id=f"cs{i}{j}", type="core")
		        self.core_switches.append(node)
		        self.switches.append(node)
		
		#switches
		#aggregation and edge for k pods. k/2 each for each pod
		for pod in range(num_ports):
		    aggs = [Node(id=f"as{pod}{i}", type="aggregation") for i in range(num_ports//2)]
		    edges = [Node(id=f"es{pod}{i}", type="edge") for i in range(num_ports//2)]
		    
		    self.aggregation_switches[pod] = aggs
		    self.edge_switches[pod] = edges
		    self.switches.extend(aggs + edges)
		  
		#add hosts and connect them immediately
		#connect k/2 hosts to each edge. 
		for pod in range(num_ports):
		    for e_idx, edge in enumerate(self.edge_switches[pod]):
		        for h_idx in range(num_ports//2):
		            host = Node(id=f"h{pod}{e_idx}{h_idx}", type="host")
		            self.servers.append(host)
		            edge.add_edge(host)
		    
		#connect aggregation and edge switches with each other inside pod
		for pod in range(num_ports):
		    for edge in self.edge_switches[pod]:
		        for agg in self.aggregation_switches[pod]:
		            edge.add_edge(agg)
		            
		#connect each aggregation in a pod to k/2 different cores
		for pod in range(num_ports):
		    for agg_idx, agg in enumerate(self.aggregation_switches[pod]):
		        for cluster in range(num_ports//2):
		            core_idx = agg_idx * (num_ports//2) + cluster
		            agg.add_edge(self.core_switches[core_idx])