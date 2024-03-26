""" 
@Description: Generate Causal Graph with Multiple Attributes from Unified Output
@Author: newt.tan 
@Date: 2024-02-29 09:36:17 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-02-29 09:36:17  
"""

from zat.log_to_dataframe import LogToDataFrame
import spacy
import networkx as nx
import matplotlib.pyplot as plt
from tqdm import tqdm
from core.graph_create import gfeature
from datetime import datetime
import logging

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)

class UnstrGausalGraph:
    ''' build causal graphs from originally unstructured logs, include methods

    temp_graph: extract all the edges, nodes when time equals to give timestamp

    '''
    def __init__(self, graphrule, log_df, log_type):
        self.graphrule = graphrule
        self.log_df = log_df
        self.log_type = log_type

    def temp_graph(self, G:nx.classes.digraph.DiGraph, T:datetime):
        ''' extract temporal subgraphs by matching time T
        
        '''
        return gfeature.temp_graph_ext(G, T)

    def comm_detect(self, G:nx.classes.digraph.DiGraph):
        ''' extract independent activity graphs
        
        '''
        comm_graphs = gfeature.comm_graph_ext(G)
        logger.info("Detect {} independent attack activities".format(len(comm_graphs)))
        return comm_graphs

    def anomaly_score(self,):
        pass
    
    def node_check(self, row: dict, key_name: str):
        ''' check the type of key and value
        :param row: the iterative row inside log dataframe
        :param key_name: the corresponding column inside log dataframe
        
        '''
        value = row[key_name]
        # check whether value is a list first
        if isinstance(key_name, list):
            # return nodes in order
            node_list_len = len(key_name)
            return [row[key_name[i]] for i in range(node_list_len)]
        else:
            # check the length of corresponding value
            value_len = len(value)
            # make sure two variables are extracted to become nodes
            if isinstance(value, list) and value_len == 2:
                return value[0], value[1]
        
        return None

    def causal_graph(self, ):
        ''' according to defined node/edge value, attrs to build directed graphs with 
        multiple attrs
        '''
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

        # create the causal graph
        for idx, row in tqdm(self.log_df.iterative(), desc="making causal graph from {}".format(self.log_type)):
            nodes = self.node_check(row, node_value_key)
            # check whether nodes exist
            if nodes:
                node_len = len(nodes)
                # check the node attr
                if node_attr_key != {}:
                    for key, value in node_attr_key.items():
                        # only the ip has port attributes for node
                        for i in range(node_len):
                            nodes.append((nodes[i], {key: row[value][i]}))

            
            # check the direction and build the edge
            if row[dire_key] in ["->", "-"] :
                # create the edges
                attrs_dict = {}
                pairs = list(zip(nodes[::2], nodes[1::2]))
                for key, value in edge_attr_key.items():
                    attrs_dict.update({key: row[value]})
                edges.extend([(pair, attrs_dict) for pair in pairs])
            elif row[dire_key] == "<-":
                attrs_dict = {}
                pairs = list(zip(nodes[1::2], nodes[::2]))
                for key, value in edge_attr_key.items():
                    attrs_dict.update({key: row[value]})
                edges.extend([(pair, attrs_dict) for pair in pairs])

        # create graph
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)

        return G

    def graph_label(self,):
        pass