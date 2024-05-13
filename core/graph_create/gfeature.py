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
import config
from core.graph_create.gfusion import GraphFusion
from pathlib import Path

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


def temp_graph_ext(sub_graphs_list: list, T: datetime, entity_path:Path):
    # load time_delay_list
    time_delay_list = config.time_thres_list
    graphfuser = GraphFusion(config.avg_len, entity_path)
    conn_graph = graphfuser.graph_conn(sub_graphs_list)
    # choose the threshold
    opt_time = graphfuser.choose_thres(conn_graph, T, time_delay_list)
    print("calculated optimized time interval is: {}".format(opt_time))
    return graphfuser.temp_graph(conn_graph, T, opt_time)