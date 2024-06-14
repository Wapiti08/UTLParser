'''
 # @ Create Time: 2024-06-14 16:13:18
 # @ Modified time: 2024-06-14 16:14:39
 # @ Description: check the graph node/edge attributions
 '''

import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
import networkx as nx
from pathlib import Path


cur_path = Path.cwd().parent
outdir = cur_path.joinpath("unit_test", "data","result")
# fuse_graph = nx.read_graphml(outdir.joinpath("full.graphml"))
# fuse_graph = nx.read_graphml(outdir.joinpath("conn.graphml"))
fuse_graph = nx.read_graphml(outdir.joinpath("dns.graphml"))


# List all nodes with their attributes
nodes_with_attributes = fuse_graph.nodes(data=True)
for node, attrs in nodes_with_attributes:
    print(f"Node: {node}, Attributes: {attrs}")


# List all edges with their attributes
edges_with_attributes = fuse_graph.edges(data=True)
for u, v, attrs in edges_with_attributes:
    print(f"Edge: ({u}, {v}), Attributes: {attrs}")