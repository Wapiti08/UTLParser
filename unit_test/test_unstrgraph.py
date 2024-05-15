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
from core.graph_create.gfusion import GraphFusion
from core.graph_create import gfeature
import config

class TestUnStrgraph(unittest.TestCase):
    ''' test the parsing performance for access log
    
    '''
    def setUp(self):
        cur_path = Path.cwd()
        indir = cur_path.joinpath("data","result").as_posix()
        outdir = cur_path.joinpath("data","result").as_posix()
        self.graphfusion = GraphFusion(config.avg_len, cur_path.parent.joinpath("core","entity_reco"))

        self.auth_unstrgraph = UnstrGausalGraph(indir, outdir, "auth")
        self.audit_unstrgraph = UnstrGausalGraph(indir, outdir, "audit")
        self.dns_unstrgraph = UnstrGausalGraph(indir, outdir, "dns")
        self.access_unstrgraph = UnstrGausalGraph(indir, outdir, "access")
        self.syslog_unstrgraph = UnstrGausalGraph(indir, outdir, "syslog")
        self.error_unstrgraph = UnstrGausalGraph(indir, outdir, "error")
    
    # def test_temp_graph(self,):
    #     self.auth_unstrgraph.data_load()
    #     self.audit_unstrgraph.data_load()
    #     self.dns_unstrgraph.data_load()
    #     self.access_unstrgraph.data_load()

    #     graph_list = [self.auth_unstrgraph.causal_graph(),
    #                   self.audit_unstrgraph.causal_graph(),
    #                   self.dns_unstrgraph.causal_graph(),
    #                   self.access_unstrgraph.causal_graph()]
    #     T = "2022-Jan-15 10:17:01.246000"
    #     # calculate the opt time
    #     G = self.graphfusion.graph_conn(graph_list)
    #     # opt_time = self.graphfusion.choose_thres(G, T, config.time_thres_list)
    #     print(self.auth_unstrgraph.temp_graph(graph_list, T))

    # def test_comm_detect(self,):
    #     self.auth_unstrgraph.data_load()
    #     self.audit_unstrgraph.data_load()
    #     self.dns_unstrgraph.data_load()
    #     self.access_unstrgraph.data_load()

    #     graph_list = [self.auth_unstrgraph.causal_graph(),
    #                   self.audit_unstrgraph.causal_graph(),
    #                   self.dns_unstrgraph.causal_graph(),
    #                   self.access_unstrgraph.causal_graph()]
        
    #     G = self.graphfusion.graph_conn(graph_list)
    #     print(self.auth_unstrgraph.comm_detect(G))

    def test_causal_graph(self,):
        # self.error_unstrgraph.data_load()       
        # self.auth_unstrgraph.data_load()
        # self.audit_unstrgraph.data_load()
        # self.dns_unstrgraph.data_load()
        # self.access_unstrgraph.data_load()
        self.syslog_unstrgraph.data_load()

        # graph_list = [
        #                 # self.auth_unstrgraph.causal_graph(),
        #               self.audit_unstrgraph.causal_graph(),
        #               self.dns_unstrgraph.causal_graph(),
        #               self.access_unstrgraph.causal_graph()]
        
        # self.error_unstrgraph.graph_save(self.error_unstrgraph.causal_graph(), None)
        # self.auth_unstrgraph.graph_save(self.auth_unstrgraph.causal_graph(), None)
        self.syslog_unstrgraph.graph_save(self.syslog_unstrgraph.causal_graph(), None)

        # G = self.graphfusion.graph_conn(graph_list)
        # self.auth_unstrgraph.graph_save(G, "full")


if __name__ == "__main__":
    unittest.main()