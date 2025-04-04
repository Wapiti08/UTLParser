import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import unittest
from core.logparse.genparser import GenLogParser
import cfg

# calculated result from uniform
format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Month> <Date> <Timestamp> <Component>: <Content>",
            # match the domain, ipv4 and ipv6
            "regex": [cfg.regex['domain'], cfg.regex['ip4'], cfg.regex['ip6']],
            "st":0.3,
            # right
            'depth':4,
        },
    },
    "Apache": {
        "auth": {
            "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
            # match the ip, port, id
            "regex": [cfg.regex['ip4'],cfg.regex['port'],cfg.regex['id']],
            "st": 0.33,
            "depth": 4,
        },
        "error": {
            "log_format": "\[<Week> <Month> <Day> <Timestamp> <Year>\] \[<Proto>\] \[pid <PID>\] \[client <Src_IP>\] <Content>",
            # match the path, port, id
            "regex": [cfg.regex['path_unix']],
            "st": 0.2,
            "depth": 3,
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
            "regex": [cfg.regex['path_unix'],cfg.regex['domain']],
            "st": 0.2,
            "depth":6,
        }
    },
    "Sysdig": {
        "process":{
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            # match path
            "regex": [cfg.regex['path_unix']],
            "st": 0.7,
            "depth":5,
        }
    }

}



class TestLogparser(unittest.TestCase):

    def setUp(self):
        
        cur_path = Path.cwd()
        # indir = cur_path.joinpath("data").as_posix()
        indir = cur_path.parent.joinpath("eval",'large_data').as_posix()
        # outdir = cur_path.joinpath("data","result").as_posix()
        outdir = cur_path.joinpath("eval",'large_data',"result").as_posix()

        # test for dns log
        rex = format_dict['DNS']['dnsmasq']['regex']
        log_format = format_dict['DNS']['dnsmasq']['log_format']
        depth = format_dict['DNS']['dnsmasq']['depth']
        st = format_dict['DNS']['dnsmasq']['st']

        self.logparser = GenLogParser(
            depth=depth,
            st=st,
            rex = rex,
            indir=indir,
            outdir=outdir,
            log_format=log_format,
            log_name="dns.log",
            keep_para=True,
            maxChild=100,
        )


        
        # test for linux syslog
        # rex = format_dict['Linux']['syslog']['regex']
        # log_format = format_dict['Linux']['syslog']['log_format']
        # depth = format_dict['Linux']['syslog']['depth']
        # st = format_dict['Linux']['syslog']['st']

        # self.logparser = GenLogParser(
        #     depth=depth,
        #     st=st,
        #     rex = rex,
        #     indir=indir,
        #     outdir=outdir,
        #     log_format=log_format,
        #     log_name="syslog.log",
        #     keep_para=True,
        #     maxChild=100,
        # )

        # # test for apache auth
        # rex = format_dict['Apache']['auth']['regex']
        # log_format = format_dict['Apache']['auth']['log_format']
        # depth = format_dict['Apache']['auth']['depth']
        # st = format_dict['Apache']['auth']['st']

        # self.logparser = GenLogParser(
        #     depth=depth,
        #     st=st,
        #     rex = rex,
        #     indir=indir,
        #     outdir=outdir,
        #     log_format=log_format,
        #     log_name="auth.log",
        #     keep_para=True,
        #     maxChild=100,
        # )

        # test for apache error
        # rex = format_dict['Apache']['error']['regex']
        # log_format = format_dict['Apache']['error']['log_format']
        # depth = format_dict['Apache']['error']['depth']
        # st = format_dict['Apache']['error']['st']

        # self.logparser = GenLogParser(
        #     depth=depth,
        #     st=st,
        #     rex = rex,
        #     indir=indir,
        #     outdir=outdir,
        #     log_format=log_format,
        #     log_name="error.log",
        #     keep_para=True,
        #     maxChild=100,
        # )


    def test_parse(self):
        self.logparser.parse()

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

        # # test for linux syslog
        # rex = format_dict['Apache']['error']['regex']
        # log_format = format_dict['Apache']['error']['log_format']
        # depth = format_dict['Apache']['error']['depth']
        # st = format_dict['Apache']['error']['st']

        # test for dns logs
        rex = format_dict['DNS']['dnsmasq']['regex']
        log_format = format_dict['DNS']['dnsmasq']['log_format']
        depth = format_dict['DNS']['dnsmasq']['depth']
        st = format_dict['DNS']['dnsmasq']['st']

        # test for auth logs
        # rex = format_dict['Apache']['auth']['regex']
        # log_format = format_dict['Apache']['auth']['log_format']
        # depth = format_dict['Apache']['auth']['depth']
        # st = format_dict['Apache']['auth']['st']

        self.logparser = GenLogParser(
            depth=depth,
            st=st,
            rex = rex,
            indir=indir,
            outdir=outdir,
            log_format=log_format,
            # log_name="error.log",
            # log_name="dns.log",
            log_name="auth.log",
            keep_para=True,
            maxChild=100,
        )

        self.logparser.load_data()
        # self.logparser.parse()
        # self.logparser.parse()
        # self.logparser.parse()
        self.logparser.parse()
        self.logparser.poi_ext()
        self.logparser.get_output(0)

    # def test_para_check(self):
    #     cur_path = Path.cwd()
    #     indir = cur_path.joinpath("data").as_posix()
    #     outdir = cur_path.joinpath("data","result").as_posix()

    #     # # test for linux syslog
    #     # rex = format_dict['Linux']['syslog']['regex']
    #     # log_format = format_dict['Linux']['syslog']['log_format']
    #     # depth = format_dict['Linux']['syslog']['depth']
    #     # st = format_dict['Linux']['syslog']['st']

    #     # test for dns logs
    #     rex = format_dict['Apache']['error']['regex']
    #     log_format = format_dict['Apache']['error']['log_format']
    #     depth = format_dict['Apache']['error']['depth']
    #     st = format_dict['Apache']['error']['st']

    #     self.logparser = GenLogParser(
    #         depth=depth,
    #         st=st,
    #         rex = rex,
    #         indir=indir,
    #         outdir=outdir,
    #         log_format=log_format,
    #         # log_name="syslog.log",
    #         log_name="error.log",
    #         keep_para=True,
    #         maxChild=100,
    #     )

    #     para_list = ['cd', '/', '&& run-parts --report /etc/cron.hourly)','test','192.121.313.313->123.123.123.123']

    #     print(self.logparser.para_check(para_list))


if __name__ == "__main__":
    unittest.main()