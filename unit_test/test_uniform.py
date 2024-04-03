'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-28 11:35:15
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-28 11:37:13
 # @ Description: unit test for uniform module
 '''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse.uniformat import UniFormat

class TestLogparser(unittest.TestCase):
    ''' test whether the module generated desired format 
    
    '''

    def setUp(self) -> None:
        # test for linux syslog, dns, auth logs
        syslog_file = Path('./data/syslog.log')
        dns_file = Path('./data/dnsmasq.log')
        auth_file = Path('./data/auth.log')
        
        # self.uniformater = UniFormat(syslog_file)
        # self.uniformater = UniFormat(dns_file)
        self.uniformater = UniFormat(auth_file)


    def test_com_check(self):
        sens = self.uniformater.ran_pick(10)
        log_format_dict = {}
        for ord, sen in enumerate(sens):
            print("processing {} sentence: \n{}".format(ord, sen))
            log_format_dict = self.uniformater.com_check(sen, 0, ":", 1, log_format_dict)
            print(log_format_dict)
    
    def test_pos_check(self):
        auth_maybe_log_format_dict = {0: ['<Month>', '<Component>'], 1: ['<Day>', '<Component>', '[<PID>]'], 2: ['<Day>', '<Timestamp>', '<Component>', '<Proto>', '<Application>', '[<PID>]'], \
                                 3: ['<Component>'], 4: ['<Component>', '<Proto>', '<Application>', '[<PID>]'], 5: [':'], 6: ['<Content>']}
        
        dns_maybe_log_format_dict = {0: ['<Month>', '<Component>'], 1: ['<Day>', '<Component>', '[<PID>]'], 2: ['<Day>', '<Timestamp>', '<Component>', '<Proto>', '<Application>', '[<PID>]'], 3: \
                                     ['<Component>', '<Proto>', '<Application>', '[<PID>]'], 4: [':'], 5: ['<Content>']}

        sys_maybe_log_format_dict = {0: ['<Month>', '<Component>'], 1: ['<Day>', '<Component>', '[<PID>]'], 2: ['<Day>', '<Timestamp>', '<Component>', '<Proto>', '<Application>', '[<PID>]'], \
                 3: ['<Component>'], 4: ['<Component>'], 5: [':'], 6: ['<Content>']}

        pos_com_mapping = {
            0: ["<Month>", "<Date>"],
            1: ["<Day>", "<Timestamp>"],
            2: ["<Timestamp>"],
            3: ["<Component>","<Proto>","<Level>","<Application>"]
        }

        log_format_dict = self.uniformater.dep_check(pos_com_mapping, auth_maybe_log_format_dict)
        
        print("result of position checking:")
        print(log_format_dict)

    def test_dep_check(self):

        auth_maybe_log_format_dict = {0: ['<Month>', '<Component>'], 1: ['<Day>', '<Component>', '[<PID>]'], 2: ['<Day>', '<Timestamp>', '<Component>', '<Proto>', '<Application>', '[<PID>]'], \
                                 3: ['<Component>'], 4: ['<Component>', '<Proto>', '<Application>', '[<PID>]'], 5: [':'], 6: ['<Content>']}
        
        dns_maybe_log_format_dict = {0: ['<Month>', '<Component>'], 1: ['<Day>', '<Component>', '[<PID>]'], 2: ['<Day>', '<Timestamp>', '<Component>', '<Proto>', '<Application>', '[<PID>]'], 3: \
                                     ['<Component>', '<Proto>', '<Application>', '[<PID>]'], 4: [':'], 5: ['<Content>']}

        sys_maybe_log_format_dict = {0: ['<Month>', '<Component>'], 1: ['<Day>', '<Component>', '[<PID>]'], 2: ['<Day>', '<Timestamp>', '<Component>', '<Proto>', '<Application>', '[<PID>]'], \
                 3: ['<Component>'], 4: ['<Component>'], 5: [':'], 6: ['<Content>']}

        dep_map_dict = {
            "<Month>": ["<Day>"],
            "<Day>":["<Timestamp>"],
            "<Timestamp>":["<Level>", "<Component>", "<Proto>"],
            "<Component>":["<Proto>","<Application>"],
            ":":["<Content>"],
            "<Proto>": ["[<PID>]", "<Content>",":"],
            "[<PID>]": [":"]
        }

        log_format_dict = self.uniformater.dep_check(dep_map_dict, sys_maybe_log_format_dict)
        print("result of dependency checking:")
        print(log_format_dict)

    def test_com_rule_check(self,):
        # define the right format
        auth_maybe_log_format_dict = {0: ['<Month>', '<Component>'], 1: ['<Day>', '<Component>', '[<PID>]'], 2: ['<Day>', '<Timestamp>', '<Component>', '<Proto>', '<Application>', '[<PID>]'], \
                                 3: ['<Component>'], 4: ['<Component>', '<Proto>', '<Application>', '[<PID>]'], 5: [':'], 6: ['<Content>']}
        dns_maybe_log_format_dict = {0: ['<Month>', '<Component>'], 1: ['<Day>', '<Component>', '[<PID>]'], 2: ['<Day>', '<Timestamp>', '<Component>', '<Proto>', '<Application>', '[<PID>]'], 3: \
                                     ['<Component>', '<Proto>', '<Application>', '[<PID>]'], 4: [':'], 5: ['<Content>']}

        sys_maybe_log_format_dict = {0: ['<Month>', '<Component>'], 1: ['<Day>', '<Component>', '[<PID>]'], 2: ['<Day>', '<Timestamp>', '<Component>', '<Proto>', '<Application>', '[<PID>]'], \
                 3: ['<Component>'], 4: ['<Component>'], 5: [':'], 6: ['<Content>']}


        log_format_dict = self.uniformater.com_rule_check(auth_maybe_log_format_dict)
        print("result of component checking:")
        print(log_format_dict)

    def test_format_ext(self):
        pass

    def test_final_format(self):
        log_format_list = []
        sens = self.uniformater.ran_pick(10)
        log_format_dict = {}
        for ord, sen in enumerate(sens):
            print("processing {} sentence: \n{}".format(ord, sen))
            log_format_dict = self.uniformater.com_check(sen, 0, ":", 1, log_format_dict)
            print("generated log format is: {}".format(log_format_dict))
            if log_format_dict:
                log_format_list.append(self.uniformater.com_rule_check(log_format_dict))
        
        print(log_format_list)
        final_log_format = self.uniformater.final_format(log_format_list)
        print("result of final log format")
        print(final_log_format)

    def test_cal_depth(self):
        sens = self.uniformater.ran_pick(10)
        print(self.uniformater.cal_depth(sens))
    
    def test_cal_thres(self):
        sens = self.uniformater.ran_pick(10)
        print(self.uniformater.cal_thres(sens))
    
    def test_format_ext(self):
        log_format_dict = {0: ['<Month>'], 1: ['<Day>'], 2: ['<Timestamp>'], 3: ['<Component>'], 4: [':'], 5: ['<Content>']}
        print(self.uniformater.format_ext(log_format_dict))


if __name__ == "__main__":
    unittest.main()


# the matching format for unstructured logs
format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Month> <Date> <Timestamp> <Component>: <Content>",
            # match the domain, ipv4 and ipv6
            "st":0.7,
            "depth":5,
        },
    },
    "Apache": {
        "auth": {
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            "st": 0.7,
            "depth": 4,
        },
    "Linux": {
        "syslog":{
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            "st": 0.7,
            "depth":5,
        }
    }

    }
}