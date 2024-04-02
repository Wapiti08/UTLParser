import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse.genparser import GenLogParser
import yaml

config = yaml.safe_load("./config.yaml")

# calculated result from uniform
format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Month> <Date> <Timestamp> <Component>: <Content>",
            # match the domain, ipv4 and ipv6
            "regex": [config['regex']['domain'], config['regex']['ip4'],config['regex']['ip6']],
            "st":0.7,
            "depth":5,
        },
    },
    "Apache": {
        "auth": {
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            # match the ip, port, id
            "regex": [config['regex']['ip4'],config['regex']['port'],config['regex']['id']],
            "st": 0.7,
            "depth": 4,
        },
    "Linux": {
        "syslog":{
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            # match path
            "regex": [config['regex']['path_unix']],
            "st": 0.7,
            "depth":5,
        }
    }

    }
}

class TestLogparser(unittest.TestCase):

    def setUp(self):
        
        rex = format_dict['DNS']['dnsmasq']['regex']
        log_format = format_dict['DNS']['dnsmasq']['log_format']
        depth = format_dict['DNS']['dnsmasq']['depth']
        st = format_dict['DNS']['dnsmasq']['st']

        self.logparser = GenLogParser(
            depth=depth,
            st=st,
            rex = rex,
            indir="./data/",
            outdir="../../data/result/",
            log_format=log_format,
            keep_para=True,
            maxChild=100,
            poi_list=[],
        )

        #  test for linux syslog
        # rex = self.logformat['Linux']['syslog']['regex']
        # log_format = self.logformat['Linux']['syslog']['log_format']
        # depth = self.logformat['Linux']['syslog']['depth']
        # st = self.logformat['Linux']['syslog']['st']

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
        # rex = self.logformat['Apache']['auth']['regex']
        # log_format = self.logformat['Apache']['auth']['log_format']
        # depth = self.logformat['Apache']['auth']['depth']
        # st = self.logformat['Apache']['auth']['st']

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



    def test_parse(self):

        self.logparser.parse("dnsmasq.log")
        # self.logparser.parse("auth.log")
        # self.logparser.parse("syslog.log")

        # self.assertEqual()

    def test_gen_logformat_regex(self,):
        self.logparser.gen_logformat_regex(self.logformat['Apache']['auth']['log_format'])
        # self.logparser.gen_logformat_regex(self.logformat['DNS']['dnsmasq']['log_format'])
        # self.logparser.gen_logformat_regex(self.logformat['Apache']['org-access']['log_format'])
        # self.logparser.gen_logformat_regex(self.logformat['Apache']['audit']['log_format'])

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