""" 
@Description: Generate Causal Graph with Multiple Attributes from structured logs
@Author: newt.tan 
@Date: 2024-02-29 09:36:17 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-02-29 09:36:17  
"""

import spacy
import networkx as nx
import matplotlib.pyplot as plt
from tqdm import tqdm
from core.graph_create import gfeature
import logging

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)

class StruGrausalGraph:
    ''' process structured network traffic
    
    '''
    def __init__(self, graphrule, log_df, log_type):
        self.graphrule = graphrule
        self.log_df = log_df
        self.log_type = log_type

    def node_check(self, row:dict, node_value_key:list):
        ''' check whether node value is - or IP address
        
        :param row: the iterative row 
        :param node_value_key: default list type with both src_ip and dest_ip
        '''
        if isinstance(node_value_key, list):
            if len(node_value_key) == 2:
                if row[node_value_key[0]] == '-' or row[node_value_key[1]] == '-':
                    logger.warn("One of IP address is missing, return None")
                    return
                else:
                    return row[node_value_key[0]], row[node_value_key[1]]
            else:
                logger.warn("length of node key is not equal to 2, return None")
                return

    def causal_graph(self,):
        ''' build graph from structured logs --- consider ips and ports only

        node value: id.orig_h, id.resp_h
        node attributes: id.orig_p, id.resp_p
        edge attributes: ts, resp_bytes, conn_state
        
        '''
        # extract the initial desired features

        G = nx.MultiDiGraph()

        # create node value and attrs
        node_value_key = self.graphrule[self.log_type]["node"]["value"]
        node_attr_key = self.graphrule[self.log_type]["node"]["attrs"]

        # create edge value and attrs
        edge_value_key = self.graphrule[self.log_type]["edge"]["value"]
        edge_attr_key = self.graphrule[self.log_type]["edge"]["attrs"]

        # load the direction
        dire_key = self.graphrule[self.log_type]["edge"]["direc"]

        nodes, edges = [], []

        for _, row in tqdm(self.log_df.iterrows(), desc='parsing logs to graphs'):
            # check whether node exists or not: - is Nan
            nodes = self.node_check(row, node_value_key)
            if nodes:
                # check attributes ---- default ports
                if node_attr_key != {}:
                    for key, value in node_attr_key.items():
                        nodes.append(nodes[0], {key: row[value[0]]})
                        nodes.append(nodes[1], {key: row[value[1]]})

            attrs_dict = {}
            pairs = list(zip(nodes[::2], nodes[1::2]))
            for key, value in edge_attr_key.items():
                attrs_dict.update({key: row[value]})
            edges.extend([(pair, attrs_dict) for pair in pairs])

            #  G.add_node(row[node_value_key[0]], port=row['id.orig_p']) 
            # G.add_node(row[node_value_key[1]], port=row['id.resp_p'])
            # # G.nodes[row['id.resp_h']]['port'].append(row['id.resp_p'])
            # # add edge
            # G.add_edge(row['id.orig_h'], row['id.resp_h'], label=row['ts'], resp_bytes=row['resp_bytes'], conn_state=row['conn_state'])
        
        # create graph
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)

        return G


           

    def graph_label(self, G: nx.Graph, node_indicator:str, att_indicitor:str, edge_indicitor:tuple, label:str):
        G_label = 0
        if label == '-   Malicious   C&C':
            # check whether containing specific C&C server Ip -- node
            if G.has_node(node_indicator):
                G_label = 1
                
        elif label == '-   Malicious   C&C-FileDownload':
            # check specific ip and resp bytes
            condition1 = G.has_edge(*edge_indicitor) and G.edges[edge_indicitor]['resp_bytes'] > 3
            condition2 = G.has_node(node_indicator)
            if condition1 and condition2:
                G_label = 2
        
        elif label == '-   Malicious   Attack':
            vul_ports = [37215, 52869, 8081, 666]
            # conn_state or the resp_p ---> vulnerable service
            for edge in G.edges(data=True):
                if 'S0' in G.edges[edge]['conn_state']:
                    G_label = 3
            for node in G.nodes:
                if node['label'] == 'resp ip' and len(list(set(node['port']) & vul_ports)) > 0:
                    G_label = 3

        elif label == '-   Malicious   DDoS':
            # count the edges between two nodes
            if gfeature.edges_count(G, edge_indicitor) > att_indicitor:
                G_label = 4
        else:
            print('Currently not support graph label with original label {}'.format(label))
            exit

        return G_label


