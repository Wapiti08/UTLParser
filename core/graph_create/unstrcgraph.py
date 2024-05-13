""" 
@Description: Generate Causal Graph with Multiple Attributes from Unified Output
@Author: newt.tan 
@Date: 2024-02-29 09:36:17 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-02-29 09:36:17  
"""

import networkx as nx
import matplotlib.pyplot as plt
from tqdm import tqdm
from core.graph_create import gfeature
from core.pattern import graphrule
from datetime import datetime
import logging
from core.graph_label import graphlabel
from pathlib import Path
import pandas as pd
import config
import ast

logging.getLogger('matplotlib.font_manager').disabled = True

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
    def __init__(self, indir:str, outdir:str, log_type:str):
        self.graphrule = graphrule.graph_attrs_json
        self.datapath = Path(indir).joinpath("{}.log_uniform.csv".format(log_type)).as_posix()
        # self.datapath = Path(indir).joinpath("{}.log_uniform.parquet".format(log_type)).as_posix()
        self.log_type = log_type
        self.savePath = outdir

    def data_load(self,):
        self.log_df = pd.read_csv(self.datapath)
        # self.log_df = pd.read_parquet(self.datapath)

    def temp_graph(self, graph_list, T:datetime):
        ''' extract temporal subgraphs by matching time T
        
        '''
        return gfeature.temp_graph_ext(graph_list, T)

    def comm_detect(self, G:nx.classes.digraph.DiGraph):
        ''' extract independent activity graphs
        
        '''
        comm_graphs = gfeature.comm_graph_ext(G)
        logger.info("Detect {} independent attack activities".format(len(comm_graphs)))
        return comm_graphs

    def anomaly_score(self,):
        pass
    
    def node_check(self, row: dict, key_name):
        ''' check the type of key and value
        :param row: the iterative row inside log dataframe
        :param key_name: the corresponding column inside log dataframe
        
        '''
        value = row[key_name]
        nodes = []
        # check whether value is a list first
        if isinstance(key_name, list):
            # return nodes in order
            for key in key_name:
                # like the IOCs ---- list
                if isinstance(row[key], tuple):
                    # recursively match value with string
                    nodes.extend([node for node in row[key] if node !='-'])
                else:
                    # filter nan and -
                    if row[key] != '-' and isinstance(row[key], str):
                        nodes.append(row[key])
        else:
            # check the length of corresponding value
            value = ast.literal_eval(value)
            # value_len = len(value)
            # # make sure two variables are extracted to become nodes
            # if value_len == 2:
            #     return value[0], value[1]
            nodes.extend(value)
        
        return nodes

    def causal_graph(self, ):
        ''' according to defined node/edge value, attrs to build directed graphs with 
        multiple attrs
        '''
        G = nx.MultiDiGraph()
        # create node value and attrs
        if self.log_type in config.log_type['gen']:
            log_type = 'general'
        else:
            log_type = self.log_type
        # check if log is process log
        if log_type != "process":
            node_value_key = self.graphrule[log_type]["node"]["value"]
            node_attr_key = self.graphrule[log_type]["node"]["attrs"]

            # create edge value and attrs
            edge_value_key = self.graphrule[log_type]["edge"]["value"]
            edge_attr_key = self.graphrule[log_type]["edge"]["attrs"]

            # load the direction
            dire_key = self.graphrule[log_type]["edge"]["direc"]
        # process log 
        else:
            graph_list = []
            for option in self.graphrule[log_type].keys():
                # initialize Graph object
                G = nx.MultiDiGraph()
                node_value_key = self.graphrule[log_type][option]["node"]["value"]
                node_attr_key = self.graphrule[log_type][option]["node"]["attrs"]

                # create edge value and attrs
                edge_value_key = self.graphrule[log_type][option]["edge"]["value"]
                edge_attr_key = self.graphrule[log_type][option]["edge"]["attrs"]

                # load the direction
                dire_key = self.graphrule[log_type][option]["edge"]["direc"]
                graph_list.append(self.graph_create(G, node_value_key, node_attr_key, \
                                                    edge_value_key, edge_attr_key, dire_key))
                # compose all the sub graphs in process to one graph
                
            return nx.compose_all(graph_list)

        G = self.graph_create(G, node_value_key, node_attr_key, edge_value_key, \
                              edge_attr_key, dire_key)

        return G
    
    def graph_create(self, G, node_value_key, node_attr_key, edge_value_key, edge_attr_key, dire_key):
        
        nodes_list, edges_list = [], []
        
        try:
            self.log_df['IOCs'] = self.log_df["IOCs"].apply(lambda x: ast.literal_eval(x))
        except Exception as e:
            logger.warn("error occurs when converting IOCs type", e)
        finally:
            pass          

        # create the causal graph
        for _, row in tqdm(self.log_df.iterrows(), desc="making causal graph from {}".format(self.log_type)):
            nodes = self.node_check(row, node_value_key)
            # check whether nodes exist
            if len(nodes) != 0:
                node_len = len(nodes)
                # check the node attr
                if node_attr_key != {}:
                    for key, value in node_attr_key.items():
                        # only the ip has port attributes for node
                        for i in range(node_len):
                            nodes.append((nodes[i], {key: row[value][i]}))

                # check the direction and build the eßßdge
                if row[dire_key] in ["->", "-"] :
                    # create the edges
                    pairs = list(zip(nodes[::2], nodes[1::2]))
                    
                elif row[dire_key] == "<-":
                    pairs = list(zip(nodes[1::2], nodes[::2]))
                
                attrs_dict = {}
                for key, value in edge_attr_key.items():
                    if edge_value_key != "":
                        if isinstance(row[edge_value_key],str):
                            if isinstance(row[value], list):
                                row[value] = ",".join(row[value])
                            attrs_dict.update({key: row[value],
                                            'value': row[edge_value_key]})
                        else:
                            attrs_dict.update({key: row[value],
                                            'value':'-'})
                    else:
                        attrs_dict.update({key: row[value],
                                            'value':'-'})
                        
                edges_list.extend([(pair[0], pair[1], attrs_dict) for pair in pairs])
            
            else:
                continue

        # create graph
        G.add_nodes_from(nodes_list)
        G.add_edges_from(edges_list)

        return G

    def graph_save(self, G, name:str):

        fig, ax = plt.subplots()
        graphdraw = graphlabel.GraphLabel()
        graphdraw.draw_labeled_multigraph(G, "value", ax)
        fig.tight_layout()
        if not name:
            nx.write_graphml_lxml(G, Path(self.savePath).joinpath('{}.graphml'.format(self.log_type)))
            plt.savefig(Path(self.savePath).joinpath('{}_graph.png'.format(self.log_type)))
        else:
            nx.write_graphml_lxml(G, Path(self.savePath).joinpath('{}.graphml'.format(name)))
            plt.savefig(Path(self.savePath).joinpath('{}_graph.png'.format(name)))

    def graph_label(self,):
        pass