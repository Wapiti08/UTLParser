'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-28 19:35:48
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-04-19 13:11:05
 # @ Description: unit test for structured log parsing
 '''

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse.strreader import StrLogParser


class TestLogparser(unittest.TestCase):

    def setUp(self):
        cur_path = Path.cwd()
        indir = cur_path.joinpath("data").as_posix()
        outdir = cur_path.joinpath("data","result").as_posix()

        # test for sysdig process
        self.logparser = StrLogParser(
            indir=indir,
            outdir=outdir,
            log_name='conn.log.labeled',
            log_type='conn',
            app='zeek',
        )
    
    def test_log_parse(self,):
        # print(self.logparser.log_parse())
        pass

    def test_get_oputput(self,):
        print(self.logparser.get_output())

if __name__ == "__main__":
    unittest.main()