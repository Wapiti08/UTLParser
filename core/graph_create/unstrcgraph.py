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
from core.graph_create import caugraph


class UnstrGausalGraph:
    ''' process raw logs 
    
    '''
    def __init__():
        pass

    def log_parse():
        pass

    def causal_graph():
        '''
        edge: 
            label: action name
            attributes: timestamp
        node:
            label: subject or object names
            attributes: {port}
        
        '''
        pass

    