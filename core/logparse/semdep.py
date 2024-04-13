""" 
@Description: the module to parse sementic role of tokens in sentence for dependency analysis
@Author: newt.tan 
@Date: 2024-02-19 16:45:32 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-02-19 16:45:32 
"""

'''

'''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import spacy
from spacy import displacy
from spacy.matcher import DependencyMatcher
from core.pattern import deppattern
import re


forward_direction = ["reply", 'forward', "cache"]
backward_direction = ["query"]

nlp = spacy.load("en_core_web_lg")


class DepParse:
    def __init__(self, log_type:str ):
        self.matcher = DependencyMatcher(nlp.vocab)
        self.log_type = log_type

    def depen_parse(self, doc:spacy.tokens.doc.Doc):
        ''' according to different anchor to design different patterns
        :param anchor: the original verb token
        '''
        deppatterner = deppattern.DepPatterns(log_type=self.log_type)
        res= deppatterner.default_dep_pattern()
        if res:
            anchors, patterns = res
            for anchor, pattern in zip(anchors, patterns):
                self.matcher.add(anchor, [pattern])
            matches = self.matcher(doc)
            if len(matches) != 0:
                # Each token_id corresponds to one pattern dict
                match_id, token_ids = matches[0]
                # for i in range(len(token_ids)):
                    # print(self.matcher.get(match_id)[1][0][i]["RIGHT_ID"] + ":", doc[token_ids[i]].text)
                # check whether the subject and object is in increasing order
                if len(token_ids) == 3:
                    if token_ids[2] > token_ids[1]:
                        return doc[token_ids[0]].text, "->"
                    else:
                        return doc[token_ids[0]].text, "<-"
        else:
            return None

    def semantic_parse(self, sen:str):
        ''' visualize the dependency of tokens in sentence
        
        '''
        doc = nlp(sen)
        for token in doc:
            print(token.text, token.idx, token.lemma_, token.pos_, token.dep_, token.tag_)    
        displacy.serve(doc, style="dep", port=8080)


    def verb_ext(self, doc:spacy.tokens.doc.Doc):
        ''' basic rule: according to the pos value return the dependency direction
        not suitable for dns
        '''
        # define all type of verbs
        target_pos_pattern = 'VB.*|VERB$'
        # if there is no AUX adjacent to left of VERB sub -> obj, otherwise obj <- sub
        for ord, token in enumerate(doc):
            # check whether matching the verb
            if re.search(target_pos_pattern, token.pos_):
                # rule1: check whether there is pos before this verb 
                if ord - 1>=0:
                    if doc[ord-1].pos_ != "AUX":
                        return token.text, '->'
                    else:
                        return token.text, '<-'
            else:
                # no verb exists in logs
                continue

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
    win_str = "Info CBS SQM: Failed to start upload with file pattern: C:\Windows\servicing\sqm\*_std.sqm,flags: 0x2 [HRESULT = 0x80004005 - E_FAIL]"
    des_win_str_nodes = ("CBS", "C:\Windows\servicing\sqm\*_std.sqm")
    des_win_str_edge = "upload"
    win_edge_attr = ["2016-09-28 04:30:31", "failed"]


    # test for linux message
    linux_str = "Aug 29 07:22:25 combo sshd(pam_unix)[796]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220.82.197.48  user=root"
    des_linux_str_nodes = ("root", "220.82.192.48")
    des_linux_str_edge = "sshd"
    linux_edge_attr = ["Aug 29 07:22:25", "failure"]

    # general test
    gen_str = "Smith founded a healthcare company in 2005."
    doc = nlp(win_str)
    depparser = DepParse(filepath=None)

    # anchor_list = ["founded", "access"]
    anchor_str, direction = depparser.verb_ext(doc)
    anchor_list = [anchor_str]
    depparser.depen_parse(anchor_list=anchor_list, doc=doc)