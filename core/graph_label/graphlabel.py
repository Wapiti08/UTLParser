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


# from node/edge attribute to iocs locations
attr_iocs_dict = {
    "node": {
        "value": ["Src_IP","IOCs", "Dest_IP"],
        "attrs": ["IOCs"]
    },
    "edge": {
        "value": ["Actions"],
        "attrs": ["Status", "IOCs"],
    }
}

# give example of labels in conn
iot_ioc_dict = {
        "Status":["S0"],
        "IOCs":[80, 8081, 52869,37215,666],
        "Dest_IP":["172.32.33.171"]
}

# example of iocs
ait_iot_dict = {
    "Src_IP": ["172.17.130.196", "10.35.35.206"],
    "Proto": ["su","system-user"],
    "Parameters": ["phopkins", "p=5", 
                   "wp_meta=WyJpZCJd",
                   "wp_meta=WyJpZCJd",
                   "wp_meta=WyJjYXQiLCAiL2V0Yy9yZXNvbHYuY29uZiJd",
                   "wp_meta=WyJpcCIsICJhZGRyIl0%3D"],
    "Actions": ["opened", "closed", "POST","AUTH","CRED_REFR","USER_START"],
    "Status": [200],
    "IOCs": ["phopkins","/lib/systemd/systemd"]
}

class GraphLabel:

    def __init__(self, attr_iocs_dict:dict, label_dict:dict):
        self.attr_iocs_dict = attr_iocs_dict
        self.label_dict = label_dict

    def ioc_match(self, sub_graph):
        '''
        
        '''
        # get the list of columns for node value
        node_value_list = self.attr_ioc_dict["node"]["value"]
        for node, attributes in sub_graph.nodes(data=True):
            # check whether node is inside iocs list
            for node_column in node_value_list:
                if node in self.label_dict[node_column]:
                    sub_graph.nodes[node]['label'] = 1
                    break
            
            for att_name, att_value in attributes:
                if att_value in self.label_dict[att_name]:
                    sub_graph.nodes[node]['label'] = 1
                    break

        # get the list of columns for edge value
        edge_value_list = self.attr_ioc_dict["edge"]["value"]
        for u, v, attributes in sub_graph.edges(data=True):
            # check whether edge is inside iocs list
            for edge_column in edge_value_list:
                for att_key, att_value in attributes.items():
                    # ignore timestamp in this stage
                    if att_key != "timestamp" and att_value !='' and att_value!='-':
                        if att_value in self.label_dict[edge_column]:
                            sub_graph[u][v]['label'] = 1
                            break

        return sub_graph

    def iter_subgraph(self, G):
        ''' extract subgraph from temporal graph (keep the original values and attributes)
        
        '''
        subgraphs = []
        for u, v in G.edges(data=True):
            subgraph = G.subgraph([u, v]).copy()

            for node in subgraph.nodes():
                subgraph.nodes[node].update(G.nodes[node])
            
            for edge in subgraph.edges():
                subgraph.edges[edge].update(G.edges[edge])
        
            subgraphs.append(subgraph)
        
        return subgraphs


    def subgraph_label(self, G: nx.Graph, ):
        ''' label edge or node with specific labels according to single value matching --- structured graphs
        :param G: temporal directed graph

        '''
        subgraphs = self.iter_subgraph(G)
        subgraph_labels = []
        for subgraph in subgraphs:
            matched_subgraph = self.ioc_match(subgraph)
            # check whether two components (two nodes or one node with one edge) are labelled as 1
            

        return subgraph_labels

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