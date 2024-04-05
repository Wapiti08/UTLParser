import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import unittest
from core.logparse.genparser import GenLogParser
import config


# calculated result from uniform
format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Month> <Date> <Timestamp> <Component>: <Content>",
            # match the domain, ipv4 and ipv6
            "regex": [config.regex['domain'], config.regex['ip4'], config.regex['ip6']],
            "st":0.3,
            # right
            'depth':4,
        },
    },
    "Apache": {
        "auth": {
            "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
            # match the ip, port, id
            "regex": [config.regex['ip4'],config.regex['port'],config.regex['id']],
            "st": 0.2,
            "depth": 4,
        },
        # "access": {
        #     "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
        #     # match the ip, port, id
        #     "regex": [config.regex['ip4'],config.regex['port'],config.regex['id']],
        #     "st": 0.7,
        #     "depth": 4,
        # },
    },
    "Linux": {
        "syslog":{
            "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
            # match path
            "regex": [config.regex['path_unix'],config.regex['domain']],
            "st": 0.2,
            "depth":6,
        }
    },
    "Sysdig": {
        "process":{
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            # match path
            "regex": [config.regex['path_unix']],
            "st": 0.7,
            "depth":5,
        }
    }

}

class TestLogparser(unittest.TestCase):

    def setUp(self):
        
        # test for dns log
        # rex = format_dict['DNS']['dnsmasq']['regex']
        # log_format = format_dict['DNS']['dnsmasq']['log_format']
        # depth = format_dict['DNS']['dnsmasq']['depth']
        # st = format_dict['DNS']['dnsmasq']['st']

        # self.logparser = GenLogParser(
        #     depth=depth,
        #     st=st,
        #     rex = rex,
        #     indir="./data/",
        #     outdir="../../data/result/",
        #     log_format=log_format,
        #     keep_para=True,
        #     maxChild=100,
        #     poi_list=[],
        # )

        cur_path = Path.cwd()
        indir = cur_path.joinpath("data").as_posix()
        outdir = cur_path.joinpath("data","result").as_posix()
        # test for linux syslog
        rex = format_dict['Linux']['syslog']['regex']
        log_format = format_dict['Linux']['syslog']['log_format']
        depth = format_dict['Linux']['syslog']['depth']
        st = format_dict['Linux']['syslog']['st']

        self.logparser = GenLogParser(
            depth=depth,
            st=st,
            rex = rex,
            indir=indir,
            outdir=outdir,
            log_format=log_format,
            log_name="syslog.log",
            keep_para=True,
            maxChild=100,
            poi_list=[],
        )

        # test for apache auth
        # rex = format_dict['Apache']['auth']['regex']
        # log_format = format_dict['Apache']['auth']['log_format']
        # depth = format_dict['Apache']['auth']['depth']
        # st = format_dict['Apache']['auth']['st']

        # self.logparser = GenLogParser(
        #     depth=depth,
        #     st=st,
        #     rex = rex,
        #     indir="./data/",
        #     outdir="../../data/result/",
        #     log_format=log_format,
        #     keep_para=True,
        #     maxChild=100,
        #     poi_list=[],
        # )


    def test_parse(self):

        # self.logparser.parse("dnsmasq.log")
        # self.logparser.parse("auth.log")
        self.logparser.parse("syslog.log")

        # self.assertEqual()

    # def test_gen_logformat_regex(self,):
    #     self.logparser.gen_logformat_regex(self.logformat['Apache']['auth']['log_format'])
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
    def test_get_output(self):
        
        cur_path = Path.cwd()
        indir = cur_path.joinpath("data").as_posix()
        outdir = cur_path.joinpath("data","result").as_posix()
        # test for linux syslog
        rex = format_dict['Linux']['syslog']['regex']
        log_format = format_dict['Linux']['syslog']['log_format']
        depth = format_dict['Linux']['syslog']['depth']
        st = format_dict['Linux']['syslog']['st']

        self.logparser = GenLogParser(
            depth=depth,
            st=st,
            rex = rex,
            indir=indir,
            outdir=outdir,
            log_format=log_format,
            log_name="syslog.log",
            keep_para=True,
            maxChild=100,
            poi_list=[],
        )
        self.logparser.load_data()
        self.logparser.parse("syslog.log")
        self.logparser.poi_ext()
        self.logparser.get_output(0)

if __name__ == "__main__":
    unittest.main()