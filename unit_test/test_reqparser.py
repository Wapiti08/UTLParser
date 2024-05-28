'''
 # @ Create Time: 2024-03-11 23:35:03
 # @ Modified time: 2024-04-19 10:21:01
 # @ Description: unit test for reqparser
 '''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse.reqparser import ReqParser

class TestLogparser(unittest.TestCase):
    ''' test the parsing performance for access log
    
    '''
    def setUp(self):
        cur_path = Path.cwd()
        indir = cur_path.joinpath("data").as_posix()
        outdir = cur_path.joinpath("data","result").as_posix()

        # test for sysdig process
        self.logparser = ReqParser(
            indir=indir,
            outdir=outdir,
            log_name='org-access.log',
            log_type='access',
            app='apache',
        )
    
    def test_url_para_ext(self):
        context_part = "GET /wp-includes/js/wp-embed.min.js?ver=5.8.3 HTTP/1.1"
        print(self.logparser.url_para_ext(context_part))

    def test_user_agent_ext(self):
        user_agents_1 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"
        user_agents = "Apache/2.4.29 (Ubuntu) OpenSSL/1.1.1 (internal dummy connection)"
        print(self.logparser.user_agent_ext(user_agents_1))
        print(self.logparser.user_agent_ext(user_agents))

    def test_poi_ext(self):
        pass

    def test_get_output(self):
        print(self.logparser.get_output(0))


if __name__ == "__main__":
    unittest.main()