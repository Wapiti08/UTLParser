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

    def read_output(self, unified:bool):
        ''' read csv file
        
        '''
        if unified:
            # read unified logs from unstructured logs
            df = pd.read_csv(self.input_file)
        else:
            # read structured logs    
            log_to_df = LogToDataFrame()
            # keep the ts column
            df = log_to_df.create_dataframe(self.input_file,ts_index=False)

        return df

    def causal_graph_create(self, structured: bool):
        ''' go to separate process logics

        '''
        df = self.read_output(structured)

        if structured:
            strcgraph.StruGrausalGraph(graphrule=graphrule.graph_attrs_json, log_df=df)
        else:
            unstrcgraph.UnstrGausalGraph(graphrule=graphrule.graph_attrs_json, log_df=df)            








