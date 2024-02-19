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
import flair
import nltk

nlp = spacy.load("en_core_web_lg")

def semantic_role(sen:str):



def token_parse():
    


if __name__ == "__main__":
    # test for dns logs
    dns_str = "Jan 14 08:16:58 dnsmasq[14460]: using nameserver 127.0.0.1#53 \
            for domain 228.131.168.192.in-addr.arpa"
    des_dns_str_nodes = ("127.0.0.1#53", "228.131.168.192.in-addr.arpa")
    # self-defined
    des_dns_str_edge = "parse"
    # it can be converted to seconds
    dns_edge_attr = ["Jan 14 08:16:58"]

    # test for windows 7 logs CBS
    win_str = "2016-09-28 04:30:31, Info                  CBS    SQM: Failed to start upload with file pattern: \
            C:\Windows\servicing\sqm\*_std.sqm,flags: 0x2 [HRESULT = 0x80004005 - E_FAIL]"
    des_win_str_nodes = ("CBS", "C:\Windows\servicing\sqm\*_std.sqm")
    des_win_str_edge = "upload"
    win_edge_attr = ["2016-09-28 04:30:31", "failed"]

    # test for linux message
    linux_str = "Aug 29 07:22:25 combo sshd(pam_unix)[796]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220.82.197.48  user=root"
    des_linux_str_nodes = ("root", "220.82.192.48")
    des_linux_str_edge = "sshd"
    linux_edge_attr = ["Aug 29 07:22:25", "failure"]