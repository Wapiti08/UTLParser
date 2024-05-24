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
import logging
from core.pattern import graphrule
from pathlib import Path
import pandas as pd
from core.graph_label import graphlabel

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
    def __init__(self, indir:str, outdir:str, log_type:str):
        self.graphrule = graphrule.graph_attrs_json
        # self.datapath = Path(indir).joinpath("{}.log_uniform.csv".format(log_type)).as_posix()
        self.datapath = Path(indir).joinpath("{}.log_uniform.parquet".format(log_type)).as_posix()
        self.log_type = log_type
        self.savePath = outdir
    
    def data_load(self,):
        # self.log_df = pd.read_csv(self.datapath)
        self.log_df = pd.read_parquet(self.datapath)

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

        nodes_list, edges_list = [], []
        # self.log_df['IOCs'] = self.log_df["IOCs"].apply(ast.literal_eval)
        # self.log_df['IOCs'] = self.log_df["IOCs"].apply(lambda x: x.strip("[]").replace("'","").split(", "))

        for _, row in tqdm(self.log_df.iterrows(), desc='parsing logs to graphs'):
            # check whether node exists or not: - is Nan
            nodes = self.node_check(row, node_value_key)
            if nodes:
                # check attributes ---- default ports
                if node_attr_key != {}:
                    for key, value in node_attr_key.items():
                        nodes_list.append((nodes[0], {key: row[value][0]}))
                        nodes_list.append((nodes[1], {key: row[value][1]}))

                attrs_dict = {}
                pairs = list(zip(nodes[::2], nodes[1::2]))
                for key, value in edge_attr_key.items():
                    if isinstance(row[edge_value_key],str):
                        attrs_dict.update({key: row[value],
                                        'value':row[edge_value_key]})
                    else:
                        attrs_dict.update({key: row[value],
                                        'value':'-'})
                edges_list.extend([(pair[0], pair[1], attrs_dict) for pair in pairs])
            else:
                continue

        G.add_nodes_from(nodes_list)
        G.add_edges_from(edges_list)

        return G

    def graph_save(self, G):

        fig, ax = plt.subplots()
        graphdraw = graphlabel.GraphLabel()
        graphdraw.draw_labeled_multigraph(G, "value", ax)
        fig.tight_layout()
        # plt.show()
        nx.write_graphml_lxml(G, Path(self.savePath).joinpath('{}.graphml'.format(self.log_type)))
        plt.savefig(Path(self.savePath).joinpath('{}_graph.png'.format(self.log_type)))