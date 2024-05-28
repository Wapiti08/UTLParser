'''
 # @ Create Time: 2024-05-13 18:34:40
 # @ Modified time: 2024-05-13 18:34:49
 # @ Description: unit test for graph fusion module
 '''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import unittest
from core.graph_create import gfusion
import networkx as nx
import config

class TestGFusion(unittest.TestCase):

    def setUp(self):
        cur_path = Path.cwd()
        entity_path = cur_path.parent.joinpath("core", "entity_reco")

        # test for apache audit
        self.gfuser = gfusion.GraphFusion(
            avg_len = 2,
            entity_path=entity_path,
        )   
        cur_path = Path.cwd()
        graph_path = cur_path.joinpath("data", "result", "full.graphml").as_posix()
        self.G = nx.read_graphml(graph_path)
        for node, data in self.G.nodes(data=True):
            print(node)
            print(data)
        
        for u,v, attrs in self.G.edges(data=True):
            print(u)
            print(v)
            print(attrs)
    
    def test_choose_thres(self):
        # read full graph graphml file
        T = "2022-Jan-15 10:17:01.246000"
        print(self.gfuser.choose_thres(self.G, T, config.time_thres_list))

    def test_inte_score(self):
        print("computed integrity score is:")
        print(self.gfuser.inte_score(self.G))
    
    def test_inde_score(self):
        print("computed independence score is:")
        print(self.gfuser.inde_score(self.G))


if __name__ == "__main__":
    unittest.main()