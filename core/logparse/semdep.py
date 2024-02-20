""" 
@Description: the module to parse sementic role of tokens in sentence for dependency analysis
@Author: newt.tan 
@Date: 2024-02-19 16:45:32 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-02-19 16:45:32 
"""

'''
    comparison between nltk, spacy, flair for tokenization, semantic role parsing

'''
import spacy
from spacy import displacy
from spacy.matcher import DependencyMatcher

import flair
import nltk

relation_dict = {
    0: "->",
    1: "<-",
}

nlp = spacy.load("en_core_web_lg")


class depparse:
    def __init__(self, filepath):
        self.file = filepath
        self.matcher = DependencyMatcher(nlp.vocab)
        print(type(self.matcher))

    def depen_parse(self, anchor: spacy.tokens.token.Token, doc:spacy.tokens.doc.Doc):
        '''
        :param anchor: the lemma verb token as the root node
        '''
        pattern = [
            # define the anchor token
            {
                "RIGHT_ID": "anchor_{}".format(anchor.text),
                "RIGHT_ATTRS": {"ORTH": anchor.text}

            },
            # define the rule for matching subject
            {

            },
            # define the rule for matching object
            {

            }

        ]
        
        self.matcher.add(anchor, [pattern])
        matches = self.matcher(doc)

    def semantic_parse(self, sen:str):
        doc = nlp(sen)
        for token in doc:
            print(token.text, token.idx, token.lemma_, token.pos_, token.dep_, token.tag_)    
        displacy.serve(doc, style="dep", port=8080)


    def verb_ext(self, doc:spacy.tokens.doc.Doc):
        ''' according to the pos value return the dependency direction
        
        
        '''
        target_pos = "VERB"
        # if there is no AUX adjacent to left of VERB sub -> obj, otherwise obj <- sub
        for ord, token in enumerate(doc):
            if token.pos_ == target_pos:
                if doc[ord-1].pos_ != "AUX":
                    return relation_dict[0]

    def token_parse(self):
        pass


if __name__ == "__main__":
    # test for dns logs
    dns_str = "using nameserver 127.0.0.1#53 for domain 228.131.168.192.in-addr.arpa"
    des_dns_str_nodes = ("127.0.0.1#53", "228.131.168.192.in-addr.arpa")
    # self-defined
    des_dns_str_edge = "parse"
    # it can be converted to seconds
    dns_edge_attr = ["Jan 14 08:16:58"]

    # test for windows 7 logs CBS
    win_str = "2016-09-28 04:30:31, Info CBS SQM: Failed to start upload with file pattern: \
            C:\Windows\servicing\sqm\*_std.sqm,flags: 0x2 [HRESULT = 0x80004005 - E_FAIL]"
    des_win_str_nodes = ("CBS", "C:\Windows\servicing\sqm\*_std.sqm")
    des_win_str_edge = "upload"
    win_edge_attr = ["2016-09-28 04:30:31", "failed"]


    # test for linux message
    linux_str = "Aug 29 07:22:25 combo sshd(pam_unix)[796]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220.82.197.48  user=root"
    des_linux_str_nodes = ("root", "220.82.192.48")
    des_linux_str_edge = "sshd"
    linux_edge_attr = ["Aug 29 07:22:25", "failure"]

    # general test
    gen_str = "Smith is founded a healthcare company in 2005."
    semantic_parse(gen_str)
    verb_ext()
