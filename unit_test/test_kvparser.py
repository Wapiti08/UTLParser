'''
 # @ Create Time: 2024-03-06 12:17:03
 # @ Modified time: 2024-03-07 13:57:39
 # @ Description: unit test for kvparser
 '''


import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse.kvparser import KVParser
import cfg


class TestLogparser(unittest.TestCase):
    ''' test the parsing performance for audit and process
    
    '''
    def setUp(self):
        cur_path = Path.cwd()
        # indir = cur_path.joinpath("data").as_posix()
        indir = cur_path.parent.joinpath("eval",'large_data').as_posix()
        # outdir = cur_path.joinpath("data","result").as_posix()
        outdir = cur_path.joinpath("eval",'large_data',"result").as_posix()

        # test for sysdig process
        # self.logparser = KVParser(
        #     indir=indir,
        #     outdir=outdir,
        #     log_name='process.log',
        #     log_type='process',
        #     app='sysdig',
        # )


        # test for apache audit
        self.logparser = KVParser(
            indir=indir,
            outdir=outdir,
            log_name='audit.log',
            log_type='audit',
            app='apache',
        )   

    # def test_split_pair(self,):
        
    #     # sentence_audit = """type=USER_START msg=audit(1642635541.040:3245): pid=3539 uid=0 auid=0 ses=443 msg='op=PAM:session_open acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'"""
    #     sentence_process = "23:40:09.104759831 3 httpd (28599) < semop 5113 23:40:09.104820227 3 httpd (28599) > getsockname"
    #     sen_process_1 = "23:40:09.104016814 3 httpd (28599) > fcntl fd=13(127.0.0.1:40016->127.0.0.1:80) cmd=3(F_SETFD)"
    #     # key_value_audit_pairs = self.logparser.split_pair(sentence_audit)
    #     key_value_proc_pairs = self.logparser.split_pair(sen_process_1)
    #     # print(key_value_audit_pairs)
    #     # print(key_value_proc_pairs)
    #     desired_pair_map_audit = ["type=USER_START", "msg=audit(1642635541.040.3245)", "pid=3539", "uid=0", "auid=0","ses=443", "msg='op=PAM:session_open", 'acct="root"', 'exe="/usr/sbin/cron"', "hostname=?", "addr=?", "terminal=cron", "res=success'"]
        # self.assertEquals(key_value_audit_pairs, desired_pair_map_audit)

    def test_args_parse(self,):
        
        args_str = "res=0 path=/opt/lampp/htdocs/userstats.php 5610 23:40:09.398233308 2 httpd (28599) > open"
        # print(self.logparser.args_parse(args_str))

    def test_value_check(self,):
        # path check
        # args_str = "res=0 path=/opt/lampp/htdocs/userstats.php 5610 23:40:09.398233308 2 httpd (28599) > open"
        # # ip check
        # # args_str = "fd=14(127.0.0.1:39175->127.0.0.1:80) size=8000"
        # # domain check
        # kv_pairs = self.logparser.args_parse(args_str)
        # for pair in kv_pairs:
        #     print(self.logparser.value_check(pair))
        pass

    def test_poi_ext(self,):
        # test_string = """type=USER_START msg=audit(1642635541.040:3245): pid=3539 uid=0 auid=0 ses=443 msg='op=PAM:session_open acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'"""
        # kv_pairs = self.logparser.split_pair(test_string)
        # print(self.logparser.poi_ext(kv_pairs))
        pass

    def test_log_parse(self, ):
        # print(self.logparser.log_parse())
        pass
        
    def test_get_output(self,):
        self.logparser.get_output(0)

if __name__ == "__main__":
    unittest.main()