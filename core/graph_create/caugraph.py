""" 
@Description: Generate Causal Graph with Multiple Attributes from Unified Output
@Date: 2024-02-29 09:36:17 
@Last Modified time: 2024-02-29 09:36:17  
"""

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from core.graph_create import strcgraph, unstrcgraph, gfusion, gfeature
import cfg

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
        self.caugrapher.graph_save(subgraph, None)
        return subgraph

    def query_comm(self, fused_graph):
        ''' get the independent graphs from fused graph to detect communities
        
        '''
        return self.caugrapher.comm_detect(fused_graph)


def query_temp_graph(app_list, output_file, T, entity_path):
    ''' query temporal graph from fused graph
    :param G: fused graph
    :param T: given format timestamp like: "2022-Jan-15 10:17:01.246000"
    '''
    sub_graph_list = []
    for log_type in app_list:
        grapher = unstrcgraph.UnstrGausalGraph(output_file, log_type)
        grapher.data_load()
        sub_graph_list.append(grapher.causal_graph())
    
    return gfeature.temp_graph_ext(sub_graph_list, T, entity_path)


def fuse_subgraphs(log_type_list:list, output_path:str, entity_path:str):
    ''' generate subgraphs and fuse them to one graph
    
    '''
    sub_graph_list = []
    for log_type in log_type_list:
        grapher = unstrcgraph.UnstrGausalGraph(output_path, log_type)
        grapher.data_load()
        sub_graph_list.append(grapher.causal_graph())
    
    graphfusion = gfusion.GraphFusion(cfg.avg_len, entity_path)

    fused_graph = graphfusion.graph_conn(sub_graph_list)
    grapher.graph_save(fused_graph, "full")
    return fused_graph



