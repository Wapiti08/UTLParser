'''
 # @ Create Time: 2024-03-11 23:35:03
 # @ Modified time: 2024-04-19 10:21:01
 # @ Description: unit test for reqparser
 '''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.graph_label import graphlabel
import config
import networkx as nx
from collections import Counter

class TestLogparser(unittest.TestCase):
    ''' test the parsing performance for access log
    
    '''
    def setUp(self):

        cur_path = Path.cwd()
        indir = cur_path.joinpath("data").as_posix()
        outdir = cur_path.joinpath("data","result").as_posix()
        self.sub_graph = nx.read_graphml(Path(outdir).joinpath("full.graphml"))

        # test for sysdig process
        self.graphlabeler = graphlabel.GraphLabel(
            attr_iocs_dict=config.attr_iocs_dict,
            label_dict=config.ait_iot_dict,
        )
    
    def test_ioc_match(self):
        
        print(self.graphlabeler.ioc_match(sub_graph=self.sub_graph))


    def test_iter_subgraph(self):

        print(self.graphlabeler.iter_subgraph(G=self.sub_graph))


    def test_subgraph_label(self):

        print(Counter(self.graphlabeler.subgraph_label(G=self.sub_graph)[1]))


if __name__ == "__main__":
    unittest.main()