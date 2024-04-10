

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse import semdep
import spacy
from utils import util
class TestLogparser(unittest.TestCase):
    ''' test the parsing performance for audit and process
    
    '''
    def setUp(self) -> None:

        self.semdeper = semdep.DepParse("dns")


    def test_verb_ext(self,):

        nlp = spacy.load("en_core_web_lg")
        # test_string = "Stopping udev Kernel Device Manager...,5e9136a3"
        string_list = [
            "cached mail is NXDOMAIN,1932",
            "cached db.local.clamav.net.cdn.cloudflare.net is 104.16.218.84",
            "forwarded current.cvd.clamav.net to 192.168.255.254",
            "query[AAAA] db.local.clamav.net from 172.17.131.81",
            "session opened for user root by (uid=0)",
            "reply db.local.clamav.net.cdn.cloudflare.net is 104.16.219.84"
            "nameserver 127.0.0.1 refused to do a recursive query"
        ]
        for test_string in string_list:
            doc = nlp(test_string)
            
            print(self.semdeper.verb_ext(doc))
              
    def test_depen_parse(self,):
        anchor_list = ["reply", "forwarded", "query", "cached"]
        nlp = spacy.load("en_core_web_lg")
        string_list = [
            "cached mail is NXDOMAIN,1932",
            "cached db.local.clamav.net.cdn.cloudflare.net is 104.16.218.84",
            "forwarded current.cvd.clamav.net to 192.168.255.254",
            "query[AAAA] db.local.clamav.net from 172.17.131.81",
            "reply db.local.clamav.net.cdn.cloudflare.net is 104.16.219.84"
            
        ]    
        for test_string in string_list:   
            test_string = util.token_filter(test_string)
            doc = nlp(test_string)
            self.semdeper.depen_parse(doc)

    # def test_semantic_parse(self,):
    #     test_string = "query ycgjslfptkev.com from 10.35.33.111"
    #     self.semdeper.semantic_parse(test_string)

    # def test_nlp_verb_ext(self,):
    #     test_string = "query ycgjslfptkev.com from 10.35.33.111"
    #     print(self.semdeper.nlp_verb_ext(test_string))


if __name__ == "__main__":
    unittest.main()