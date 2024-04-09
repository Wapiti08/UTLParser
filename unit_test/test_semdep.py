

import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

import unittest
from core.logparse import semdep
import spacy

class TestLogparser(unittest.TestCase):
    ''' test the parsing performance for audit and process
    
    '''
    def setUp(self) -> None:

        self.semdeper = semdep.DepParse()


    def test_verb_ext(self,):

        nlp = spacy.load("en_core_web_lg")
        # test_string = "Stopping udev Kernel Device Manager...,5e9136a3"
        test_string = "cached mail is NXDOMAIN,1932"
        # test_string = "query 3x6-.549-.OIHTNDp3gt8G53ORPNtSCWKk90JXYfTNGMvp0gqDu69d/lZLpa17Rdd5jC5s-.xgmWE1jDNDH84hWZna0bVxOot1dczDITgOVrxQZcdghuHBeExN7ElGgoELKb-.O2AnNftrb*e05sfOaJI52CXREVJSL0OVQCOlqkNA5mErHLMTTgJ5zkZlWS5*-.customers_2018.xlsx.ycgjslfptkev.com from 10.35.33.111"
        doc = nlp(test_string)
        print(doc)
        for token in doc:
            print(token.pos_)
            print('==========')
            print(token.tag_)
            print('=========')
            print(token.dep_)
            print('=========')
            print(token.lemma_)
        print(self.semdeper.verb_ext(doc))
              
    def test_depen_parse(self,):
        anchor_list = ["reply", "forward", "query", "cached"]
        nlp = spacy.load("en_core_web_lg")
        test_string = "query 3x6-.549-.OIHTNDp3gt8G53ORPNtSCWKk90JXYfTNGMvp0gqDu69d/lZLpa17Rdd5jC5s-.xgmWE1jDNDH84hWZna0bVxOot1dczDITgOVrxQZcdghuHBeExN7ElGgoELKb-.O2AnNftrb*e05sfOaJI52CXREVJSL0OVQCOlqkNA5mErHLMTTgJ5zkZlWS5*-.customers_2018.xlsx.ycgjslfptkev.com from 10.35.33.111"
        doc = nlp(test_string)
        self.semdeper.depen_parse(anchor_list, 'dns', doc)

    # def test_semantic_parse(self,):
    #     test_string = "query ycgjslfptkev.com from 10.35.33.111"
    #     self.semdeper.semantic_parse(test_string)

    # def test_nlp_verb_ext(self,):
    #     test_string = "query ycgjslfptkev.com from 10.35.33.111"
    #     print(self.semdeper.nlp_verb_ext(test_string))


if __name__ == "__main__":
    unittest.main()