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
import pandas as pd
from core.pattern import graphrule
from core.graph_create import strcgraph, unstrcgraph

class GausalGraph:
    ''' process raw logs 
    
    '''
    def __init__(self, filepath):
        self.input_file = filepath
        self.df = pd.read_csv(self.input_file)

    def causal_graph_create(self, structured: bool):
        ''' go to separate process logics

        '''
        df = self.read_output(structured)

        if structured:
            G = strcgraph.StruGrausalGraph(graphrule=graphrule.graph_attrs_json, log_df=df)
        else:
            G= unstrcgraph.UnstrGausalGraph(graphrule=graphrule.graph_attrs_json, log_df=df)            

    def visualize_graph(self,):
        pass
    







