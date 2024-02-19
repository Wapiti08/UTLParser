import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse.semdrain import LogParser
import core.logparse.uniformat as uniformat

class TestLogparser(unittest.TestCase):

    def setUp(self):
        self.logformat = uniformat.format_dict

        # test for dns parse

        # rex = self.logformat['DNS']['dnsmasq']['regex']
        # log_format = self.logformat['DNS']['dnsmasq']['log_format']
        # depth = self.logformat['DNS']['dnsmasq']['depth']
        # st = self.logformat['DNS']['dnsmasq']['st']

        # self.logparser = LogParser(
        #     depth=depth,
        #     st=st,
        #     rex = rex,
        #     indir="./data/",
        #     outdir="../../data/result/",
        #     log_format=log_format,
        #     keep_para=True,
        #     maxChild=100,
        #     filter=0,
        #     key=0,
        # )

        # test for apache org-access

        # rex = self.logformat['Apache']['org-access']['regex']
        # log_format = self.logformat['Apache']['org-access']['log_format']
        # depth = self.logformat['Apache']['org-access']['depth']
        # st = self.logformat['Apache']['org-access']['st']

        # self.logparser = LogParser(
        #     depth=depth,
        #     st=st,
        #     rex = rex,
        #     indir="./data/",
        #     outdir="../../data/result/",
        #     log_format=log_format,
        #     keep_para=True,
        #     maxChild=100,
        #     filter=0,
        #     iocs=0,
        # )

        # test for apache audit
        # rex = self.logformat['Apache']['audit']['regex']
        # log_format = self.logformat['Apache']['audit']['log_format']
        # depth = self.logformat['Apache']['audit']['depth']
        # st = self.logformat['Apache']['audit']['st']

        # self.logparser = LogParser(
        #     depth=depth,
        #     st=st,
        #     rex = rex,
        #     indir="./data/",
        #     outdir="../../data/result/",
        #     log_format=log_format,
        #     keep_para=True,
        #     maxChild=100,
        #     filter=0,
        #     iocs=0,
        # )

        # test for apache auth
        rex = self.logformat['Apache']['auth']['regex']
        log_format = self.logformat['Apache']['auth']['log_format']
        depth = self.logformat['Apache']['auth']['depth']
        st = self.logformat['Apache']['auth']['st']

        self.logparser = LogParser(
            depth=depth,
            st=st,
            rex = rex,
            indir="./data/",
            outdir="../../data/result/",
            log_format=log_format,
            keep_para=True,
            maxChild=100,
            filter=0,
            iocs=0,
        )

    def test_parse(self):

        # self.logparser.parse("dnsmasq.log")
        # self.logparser.parse("org-access.log")
        # self.logparser.parse("audit.log")
        self.logparser.parse("auth.log")

        # self.assertEqual()

    def test_gen_logformat_regex(self,):
        self.logparser.gen_logformat_regex(self.logformat['Apache']['auth']['log_format'])

    # def test_get_parameter_list(self,):
    #     # generate df_log
    #     self.logparser.load_data()
    #     print(self.logparser.df_log.iloc[3])
    #     row = self.logparser.df_log.iloc[3]
    #     result = self.logparser.get_parameter_list(row)
    #     print(result)
    #     self.assertEqual(["cdn.cloudflare.net", "2606:4700::6810:db54"], result)


if __name__ == "__main__":
    unittest.main()