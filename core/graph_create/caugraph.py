""" 
@Description: Generate Causal Graph with Multiple Attributes from Unified Output
@Author: newt.tan 
@Date: 2024-02-29 09:36:17 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-02-29 09:36:17  
"""

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from core.graph_create import strcgraph, unstrcgraph
import config

class GausalGraph:
    ''' process raw logs 
    
    '''
    def __init__(self, indir, outdir, log_type):
        self.input_file = indir
        self.output_file = outdir
        self.log_type = log_type

    def causal_graph_create(self, structured: bool):
        ''' go to separate process logics

        '''

        if structured:
            self.caugrapher = strcgraph.StruGrausalGraph(self.input_file, self.output_file, self.log_type)

        else:
            self.caugrapher = unstrcgraph.UnstrGausalGraph(self.input_file, self.output_file, self.log_type)            
        
        # load unified output
        self.caugrapher.data_load()
        subgraph = self.caugrapher.causal_graph()
        self.caugrapher.graph_save(subgraph)
        return subgraph


    def fuse_subgraphs(self, indir_list:list):
        ''' generate subgraphs and fuse them to one graph
        
        '''
        sub_graph_list = []
        for indir in indir_list:
            grapher = unstrcgraph.UnstrGausalGraph(indir, self.output_file, self.log_type)
            grapher.data_load()
            sub_graph_list.append(grapher.causal_graph())
        
        fused_graph = grapher.graph_conn(sub_graph_list)
        grapher.graph_save(fused_graph, "full")
        return fused_graph

    def query_temp_graph(self, indir_list, T):
        ''' query temporal graph from fused graph
        :param G: fused graph
        :param T: given format timestamp like: "2022-Jan-15 10:17:01.246000"
        '''
        sub_graph_list = []
        for indir in indir_list:
            grapher = unstrcgraph.UnstrGausalGraph(indir, self.output_file, self.log_type)
            grapher.data_load()
            sub_graph_list.append(grapher.causal_graph())
        
        return self.caugrapher.temp_graph(sub_graph_list, T)

    def query_comm(self, fused_graph):
        ''' get the independent graphs from fused graph to detect communities
        
        '''
        return self.caugrapher.comm_detect(fused_graph)







