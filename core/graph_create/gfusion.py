'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-04 10:02:15
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-06 11:20:12
 # @ Description: Potential Fusion Part or Optimization Part to reduce the graph size or 
                achieve the fusion of graphs from diverse data sourcesw
 '''
import networkx as nx


class GraphFusion:
    def __init__(self,):
        pass

    def graph_conn(self, graph_list:list):
        ''' fuse multiple sub graphs according to rule information like auth, audit, dns, access 
        :param graph_list: the list of graphml --- sub graphs
        '''
        # initialize the whole graph
        G = nx.MultiDiGraph()
        for subgraph in graph_list:
            G.add_nodes_from(subgraph.nodes())
            G.add_edges_from(subgraph.edges())
        return G

    def time_check(self, scope: int):
        pass
