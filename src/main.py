'''
 # @ Create Time: 2024-01-19 19:11:01
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
import logging
import networkx as nx

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)


class GraphTrace:
    def __init__(self, log_app, log_path, output_path, iocs_list, stru:bool):
        self.log_app = log_app
        self.log_path = log_path
        self.output_path = output_path
        self.iocs_list = iocs_list
        self.strc = stru
        self.grapher = caugraph.GausalGraph(self.output_path, self.output_path, self.log_app)

    def log_parse(self):
        ''' generate the unified output for given log data
        
        '''
        uparser = unilogparser.LogParser(self.log_app, self.log_path, self.output_path, self.iocs_list)
        uparser.generate_output(uparser.choose_logparser())

    def causal_graph(self, ):
        ''' generate causal graphs from unified output
        
        '''
        return self.grapher.causal_graph_create(self.strc)

    def comm_graph_query(self, fused_graph):
        ''' detect independent communities from fused_graph
        
        '''
        return self.grapher.query_comm(fused_graph)


def graph_label(fused_graph):
    ''' generate labelled sugraphs for potential supervised training
    
    :return subgraphs, labels
    '''
    graphlabeler = graphlabel.GraphLabel(
        attr_iocs_dict=config.attr_iocs_dict,
        label_dict=config.ait_iot_dict,
    )

    return graphlabeler.subgraph_label(fused_graph)


def temp_graph_query(app_list, output_file, T, entity_path):
    ''' query temporal graph for given timestamp T with a list of subgraphs
    :param app_list: list of log types
    '''
    return caugraph.query_temp_graph(app_list, output_file, T, entity_path)

def fused_causal_graph(log_type_list:list, output_path:str, entity_path:str):
    ''' fuse subgraphs from multiple source logs
    :param log_path_list: list of log paths
    
    '''

    return caugraph.fuse_subgraphs(log_type_list, output_path, entity_path)


if __name__ == "__main__":
    
    cur_path = Path.cwd().parent
    indir = cur_path.joinpath("unit_test", "data")
    outdir = cur_path.joinpath("unit_test","data","result").as_posix()
    entity_path = cur_path.joinpath("core","entity_reco")

    parser = ArgumentParser(description="converting logs to provenance graphs")

    # specify application name to generate log
    parser.add_argument("-a","--application", type=str, help="input the name of application which generates logs")

    # specify log location
    parser.add_argument("-i", "--input", type=str, help="input the log file name to process", default=indir)

    # specify desired entity types to extract
    parser.add_argument("-e", '--entities', type=list, default=['ip4', 'domain'] , help="input the list of desired entity types to extract, choose from config regex keys")

    # check to use different logic
    parser.add_argument("-s", '--structure', type=bool, help="whether the log is structured or unstructured, \
                        corresponding to different process logic", default=False)

    # specify output location
    parser.add_argument("-o", "--output", type=str, help="input the output of results", default=outdir)

    # whether to fuse subgraphs
    parser.add_argument('-f', '--fuse', type=bool, help="whether to fuse subgraphs", default=False)

    # specify application name to generate log
    parser.add_argument("-al","--app_list", type=lambda s: s.split(','), help="input the list of application names corresponding to log path list")

    # specify log location
    parser.add_argument("-ep", "--entity_path", type=str, help="input the path of extracted entities from unified output", default=entity_path)

    # timestamp to query temporal graph
    parser.add_argument('-t', '--timestamp',  type=str, help="input string type timestamp in %Y-%b-%d %H:%M:%S.%f format")

    # whether to generate labelled subgraphs
    parser.add_argument('-l', '--label', type=bool, help="whether to generate labelled subgraphs", default=False)

    # streaming processing
    parser.add_argument('-r', '--streaming', type=bool, help="whether to process in streaming", default=False)

    args = parser.parse_args()

    log_app = args.application
    log_file = args.input

    logger.info("generate causal graphs from {} {}".format(log_app, log_file))

    log_path = indir.joinpath(log_file)
    output_path = args.output
    iocs_list = args.entities
    struc = args.structure
    entity_path = args.entity_path
    
    # fuse subgraphs
    if args.fuse:
        print("** make sure you provide application list and generate uniformed output before **")
        fused_graph = fused_causal_graph(args.app_list, output_path, entity_path)

    if args.output and args.input and args.application:
        # process single log transformation
        # general causal graph creation
        graphtracker = GraphTrace(log_app, log_path, output_path, iocs_list, struc)
        # parsing logs
        graphtracker.log_parse()   
        # parsing logs to causal graphs
        graphtracker.causal_graph()

    if args.timestamp and len(args.app_list) != 1:
        print("** make sure you provide log list to fuse and timetstamp")
        print(temp_graph_query(args.app_list, output_path, args.timestamp, entity_path))

    if args.label and args.output:
        print("** make sure you generate fused graph before **")
        # load the fused graph
        fused_graph = nx.read_graphml(Path(outdir).joinpath("full.graphml"))
        subgraphs, labels = graph_label(fused_graph)    
        print(subgraphs)
        print(labels)

        # List all nodes with their attributes
        # nodes_with_attributes = subgraphs[0].nodes(data=True)
        # for node, attrs in nodes_with_attributes:
        #     print(f"Node: {node}, Attributes: {attrs}")
        
        # edges_with_attributes = subgraphs[0].edges(data=True)
        # for u, v, attrs in edges_with_attributes:
        #     print(f"Edge: ({u}, {v}), Attributes: {attrs}")