""" 
@Description: The Module to Extract Temporal Graphs or Generate other Features for Graphs
@Author: newt.tan 
@Date: 2024-02-29 09:40:14 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-02-29 09:40:14  
"""

import networkx as nx
import matplotlib.pyplot as plt


def edges_count(G:nx.Graph, edge:tuple):
    '''
        the edge is directed edge from node[0] to node[1]
    '''
    return G.number_of_edges(edge[0],edge[1])

def token_emb():
    pass

def feature_analysis(df, feature_list:list):
    pass

def visualize_graph(G: nx.Graph, file_path: None):
    # draw the graph
    # print(G.info())
    pos = nx.spring_layout(G)
    # nx.draw_networkx(G, pos)
    nx.draw(G, pos, arrows=True, with_labels=True, node_color='skyblue',font_weight='bold')
    # draw multiple edges
    edge_labels = {(u,v): d['label'] for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    plt.show()
    # save the graph
    if file_path:
        nx.write_graphml(G, file_path)
