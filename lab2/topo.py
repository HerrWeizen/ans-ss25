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
		self.servers = [] # Contains tuples of (node, IP)
		self.switches = { # Contains tuples of (node, IP)
			"edge": [],
			"aggregation": [],
			"core": [],
			"all": []
		}
		self.edges = []
		self.generate(num_ports)

	def generate(self, k):

		if k % 2 != 0:
			raise ValueError("Number of ports (k) must be even.")
		
		for j in range(1, num_ports // 2 + 1):
			for i in range(1, num_ports // 2 + 1):

				name = f"Core{j}{i}"
				IP = f"10.{k}.{j}.{i}"
				
				switch = Node(name, "switch")
				self.switches["core"].append((switch, IP))
				self.switches["all"].append((switch, IP))
		
		# For each Pod
		for pod in range(k):
			
			# Used to connect Edges with Servers and Edges with aggregation
			podSwitches{"edge": [], "aggregation": []}
			podServers = []

			# Higher half of Switches in Pod will be aggregation
			for agg in range(k//2):
				
				# Generate Switch
				name = f"AggregationSwitch{i}Pod{pod}"
				IP = f"10.{pod}.{agg + k // 2}.1"
				switch = Node(name, "switch")

				# Fill Information
				podSwitches["aggregation"].append(switch)
				self.switches["aggregation"].append((switch, IP))
				self.switches["all"].append((switch, IP))

			# Lower half of Switch in Pod will be edges
			for edge in range(k // 2):

				# Generate Switch
				name = f"EdgeSwitch{edge}Pod{pod}"
				IP = f"10.{pod}.{edge}.1"
				switch = Node(name, "switch")

				# Fill Switch Information
				podSwitches["edge"].append(switch)
				self.switches["edge"].append((switch, IP))
				self.switches["all"].append((switch, IP))

				# Create half of the Ports as Hosts
				for ser in range(k // 2):

					name = f"Server{ser+2}Pod{pod}Edge{edge}"
					IP = f"10.{pod}.{edge}.{ser+2}"
					server = Node(name, "server")

					# Fill Server Information
					podServers.append(server)
					self.servers.append((server, IP))
					edge = server.add_edge(switch) # Already creates Edges for both nodes

					# Fill Edge information
					self.edges.append((server.id, switch.id))
				
				# Create all edges between Edge and Aggregation inside a Pod
				for edgeSwitch in podSwitches["edge"]:
					for aggregationSwitch in podSwitches["aggregation"]
						edge = edgeSwitch.add_edge(aggregationSwitch)
						self.edges.append((edgeSwitch.id, aggregationSwitch.id))

				# Connect all edges between Aggregation and Core
				for aggIndex, aggregationSwitch in enumerate(podSwitches["aggregation"]):
					for coreIndex in range(k // 2):
						coreSwitch_index = coreIndex * (k // 2) + aggIndex
						coreSwitch = self.switches["core"][coreSwitchIndex]
						edge = aggregationSwitch.add_edge(coreSwitch)
						self.edges.append((aggregationSwitch.id, coreSwitch.id))
									