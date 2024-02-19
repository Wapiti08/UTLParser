import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse.semdrain import LogParser
import core.logparse.uniformat as uniformat

class TestLogparser(unittest.TestCase):

    def setUp(self):
        # test for dns parse
        self.logparser = LogParser(
            depth=4,
            st=0.4,
            rex = [],
            indir="../data/",
            outdir="../../data/result/",
            log_format="",
            maxChild=100,
            filter=0,
            key=0,
        )

        # test for apache org-access

        # test for apache audit

        # test for apache auth
        self.logformat = uniformat.format_dict

    def test_parse(self):
        self.logparser.parse("dnsmasq.log")

        # self.assertEqual()

    def test_gen_logformat_regex(self,):
        self.logparser.gen_logformat_regex(self.logformat['DNS']['dnsmasq'])


if __name__ == "__main__":
    unittest.main()