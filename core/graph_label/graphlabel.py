# '''
#  # @ Author: Newt Tan
#  # @ Create Time: 2024-04-19 09:27:01
#  # @ Modified by: Newt Tan
#  # @ Modified time: 2024-05-01 09:21:56
#  # @ Description: module to label subgraph in temporal causal graph
#  '''


import networkx as nx
from core.graph_create import gfeature
import itertools as it
from pathlib import Path

class GraphLabel:

    def __init__(self, attr_iocs_dict:dict, label_dict:dict):
        self.attr_iocs_dict = attr_iocs_dict
        self.label_dict = label_dict

    def ioc_match(self, sub_graph):
        ''' traverse the value and attributes to match iocs and assign label
         to node and edge with 1 for anomaly
        
        '''
        # get the list of columns for node value
        node_value_list = self.attr_iocs_dict["node"]["value"]
        for node, attributes in sub_graph.nodes(data=True):
            # check whether node is inside iocs list
            for node_column in node_value_list:
                try:
                    if node in self.label_dict[node_column]:
                        sub_graph.nodes[node]['label'] = 1
                    else:
                        sub_graph.nodes[node]['label'] = 0
                except:
                    continue
            for att_name, att_value in attributes.items():
                try:
                    if att_value in self.label_dict[att_name]:
                        sub_graph.nodes[node]['label'] = 1
                    else:
                        sub_graph.nodes[node]['label'] = 0
                except:
                    continue

        # get the list of columns for edge value
        edge_value_list = self.attr_iocs_dict["edge"]["value"]
        for u, v, attributes in sub_graph.edges(data=True):
            # check whether edge is inside iocs list
            for edge_column in edge_value_list:
                for att_key, att_value in attributes.items():
                    # ignore timestamp in this stage
                    if att_key != "timestamp" and att_value !='' and att_value!='-':
                        if att_value in self.label_dict[edge_column]:
                            attributes['label'] = 1
                            break

        return sub_graph

    def iter_subgraph(self, G):
        ''' extract subgraph from temporal graph (keep the original values and attributes)
        
        '''
        subgraphs = []
        for u, v, attributes in G.edges(data=True):
            subgraph = G.subgraph([u, v]).copy()

            for node in subgraph.nodes():
                subgraph.nodes[node].update(G.nodes[node])
            for key, value in attributes.items():
                subgraph[u][v][0][key]= value
        
            subgraphs.append(subgraph)
        
        return subgraphs


    def subgraph_label(self, G: nx.Graph):
        ''' label edge or node with specific labels according to single value matching --- structured graphs
        :param G: temporal directed graph

        '''
        subgraphs = self.iter_subgraph(G)
        subgraph_labels = []
        for subgraph in subgraphs:
            ioc_count = 0
            matched_subgraph = self.ioc_match(subgraph)
            # check whether two components (two nodes or one node with one edge) are labelled as 1
            for u, v, attrs in matched_subgraph.edges(data=True):
                try:
                    if matched_subgraph.nodes[u]["label"] == 1:
                        ioc_count += 1
                except:
                    pass
                try:
                    if matched_subgraph.nodes[v]["label"] == 1:
                        ioc_count += 1
                except:
                    pass
                try:
                    if matched_subgraph[u][v]['label'] == 1:
                        ioc_count += 1
                except:
                    pass
                # assign lables
                if ioc_count >= 2:
                    subgraph_labels.append(1)
                else:
                    subgraph_labels.append(0)
          
        return subgraphs, subgraph_labels

    def draw_labeled_multigraph(self, G, attr_name, ax=None):
        """
        Length of connectionstyle must be at least that of a maximum number of edges
        between pair of nodes. This number is maximum one-sided connections
        for directed graph and maximum total connections for undirected graph.
        :param G: the graph created by networkx
        :param attr_name: the label information of edge in graphs
        """
        # Works with arc3 and angle3 connectionstyles
        # connectionstyle = [f"arc3,rad={r}" for r in it.accumulate([0.15] * 4)]
        connectionstyle = [f"angle3,angleA={r}" for r in it.accumulate([30] * 4)]

        pos = nx.shell_layout(G)
        nx.draw_networkx_nodes(G, pos, ax=ax)
        nx.draw_networkx_labels(G, pos, font_size=20, ax=ax)
        nx.draw_networkx_edges(
            G, pos, edge_color="grey", connectionstyle=connectionstyle, ax=ax
        )

        # time_name = "timestamp"
        labels = {
            # tuple(edge): f"{attrs[time_name]}={attrs[attr_name]}"
            tuple(edge): f"{attrs[attr_name]}"
            for *edge, attrs in G.edges(keys=True, data=True)
        }

        nx.draw_networkx_edge_labels(
            G,
            pos,
            labels,
            connectionstyle=connectionstyle,
            label_pos=0.3,
            font_color="blue",
            bbox={"alpha": 0},
            ax=ax,
        )