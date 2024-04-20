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

        self.unstrgraph = UnstrGausalGraph(indir, outdir, "conn")
    
    def test_temp_graph():
        pass

    def test_comm_detect():
        pass

    def test_causal_graph(self,):
        self.unstrgraph.causal_graph()
        


if __name__ == "__main__":
    unittest.main()