'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-29 22:06:46
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-04-19 13:10:27
 # @ Description: unit test for structural graph construction
'''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.graph_create.strcgraph import StruGrausalGraph

class TestLogparser(unittest.TestCase):
    ''' test the parsing performance for access log
    
    '''
    def setUp(self):
        cur_path = Path.cwd()
        indir = cur_path.joinpath("data","result").as_posix()
        outdir = cur_path.joinpath("data","result").as_posix()

        self.strgraph = StruGrausalGraph(indir, outdir, "conn")
    
    def test_node_check(self):
        pass

    def test_causal_graph(self,):
        self.strgraph.data_load()
        G = self.strgraph.causal_graph()
    
    def test_graph_save(self):
        self.strgraph.data_load()
        G = self.strgraph.causal_graph()
        self.strgraph.graph_save(G)
        
if __name__ == "__main__":
    unittest.main()

