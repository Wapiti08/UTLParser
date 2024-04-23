'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-29 22:06:53
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-04-19 19:02:31
 # @ Description: unit test for unstructural graph construction
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.graph_create.unstrcgraph import UnstrGausalGraph

class TestLogparser(unittest.TestCase):
    ''' test the parsing performance for access log
    
    '''
    def setUp(self):
        cur_path = Path.cwd()
        indir = cur_path.joinpath("data","result").as_posix()
        outdir = cur_path.joinpath("data","result").as_posix()
        self.unstrgraph = UnstrGausalGraph(indir, outdir, "dns")
    
    def test_temp_graph(self,):
        self.unstrgraph.data_load()
        G = self.unstrgraph.causal_graph()
        T = "2024-Jan-15 00:00:53.00000"
        print(self.unstrgraph.temp_graph(G, T))

    def test_comm_detect(self,):
        self.unstrgraph.data_load()
        G = self.unstrgraph.causal_graph()
        print(self.unstrgraph.comm_detect(G))

    def test_causal_graph(self,):
        self.unstrgraph.data_load()
        G = self.unstrgraph.causal_graph()
        self.unstrgraph.graph_save(G)


if __name__ == "__main__":
    unittest.main()