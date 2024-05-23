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
import logging

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
    def __init__(self, log_app, log_path, output_path, iocs_list, fuse:bool):
        self.log_app = log_app
        self.log_path = log_path
        self.output_path = output_path
        self.iocs_list = iocs_list
        self.fuse = fuse

    def log_parse(self):
        ''' generate the unified output for given log data
        
        '''
        uparser = unilogparser.LogParser(self.log_app, self.log_path, self.output_path, self.iocs_list)
        uparser.choose_logparser()
        uparser.generate_output()

    def causal_graph_create(self, ):
        ''' generate causal graphs from unified output
        
        '''
        

        if fuse:




    def graph_query(self,):
        pass
        
    def graph_label(self,):
        pass

if __name__ == "__main__":
    
    cur_path = Path.cwd()
    indir = cur_path.joinpath("data").as_posix()
    outdir = cur_path.joinpath("data","result").as_posix()

    parser = ArgumentParser(description="converting logs to provenance graphs")

    # specify application name to generate log
    parser.add_argument("-a","--application" type=str, help="input the name of application which generates logs")

    # specify log location
    parser.add_argument("-i", "--input", type=str, help="input the full path of log data to process", default=indir)

    # specify desired entity types to extract
    parser.add_argument("-e", '--entities', type=list, help="input the list of desired entity types to extract")

    # specify output location
    parser.add_argument("-o", "--output", type=str, help="input the output of results", default=outdir)

    # whether to fuse subgraphs
    parser.add_argument('-f', '--fuse', type=bool, help="whether to fuse subgraphs", default=False)

    # timestamp to query temporal graph
    parser.add_argument('-t', '--timestamp',  type=str, help="input string type timestamp in %Y-%b-%d %H:%M:%S.%f format")

    # whether to generate labelled subgraphs
    parser.add_argument('-l', '--label', type=bool, help="whether to generate labelled subgraphs", default=False)

    # streaming processing
    parser.add_argument('-s', '--streaming', type=bool, help="whether to process in streaming", default=False)

    args = parser.parse_args()
    
    logger.info()

    log_app = args.application
    log_path = args.input
    output_path = args.output
    iocs_list =args.entities
    fuse = args.fuse
    
    graphtracker = GraphTrace()