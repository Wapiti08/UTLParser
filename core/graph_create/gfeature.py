""" 
@Description: The Module to Extract Temporal Graphs or Generate other Features for Graphs
@Author: newt.tan 
@Date: 2024-02-29 09:40:14 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-02-29 09:40:14  
"""

import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime

def edges_count(G:nx.Graph, edge:tuple):
    '''
        the edge is directed edge from node[0] to node[1]
    '''
    return G.number_of_edges(edge[0],edge[1])

def token_emb():
    pass

def feature_analysis(df, feature_list:list):
    pass

def comm_graph_ext(G:nx.classes.digraph.DiGraph):
    # make the graph undirected in order to extract independent communities
    UG = G.to_undirected()
    comm_graphs = []
    comm_graphs = [G.subgraph(c) for c in nx.connected_components(UG)]
    return comm_graphs


def temp_graph_ext(G:nx.classes.digraph.DiGraph, T: datetime):
    subgraphs = []
    for u, v, edge in G.edges(data=True):
        # extract the attribute element
        if 'timestamp' in edge and edge['timestamp'] == T:
            temp_graph = nx.MultiDiGraph()
            temp_graph.add_edge(u,v, **edge)
            subgraphs.extend(nx.connected_components(temp_graph))
    print("All the graphs appear at timestamp {} include".format(T))
    return subgraphs
