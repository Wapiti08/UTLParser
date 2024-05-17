'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-01-19 19:11:01
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-05-17 08:21:50
 # @ Description: the running interface for log transformation, graph construction, graph query
 '''


import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
from utils import util
from core.logparse import unilogparser
from core.graph_create import caugraph
from core.graph_label import graphlabel
import config
from argparse import ArgumentParser

class GraphTrace:
    def __init__(self, log_name, config):
        self.log_name = log_name

    def log_parse(self):
        ''' geneerate
        
        '''
        unilogparser(self.log_name, )

    def causal_graph_create(self,):
        pass

    def graph_query(self,):
        pass
        
    def graph_label(self,):
        pass

if __name__ == "__main__":
    
    parser = ArgumentParser(description="converting logs to provenance graphs")

    # log location

    # whether to fuse subgraphs
    parser.add_argument()

    # timestamp to query temporal graph
    parser.add_argument()

    # whether to generate labelled subgraphs
    parser.add_argument()

    args = parser.parse_args()