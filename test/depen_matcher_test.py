import spacy
from spacy.matcher import DependencyMatcher
from spacy.tokenizer import Tokenizer
import re

nlp = spacy.load("en_core_web_lg")
nlp.tokenizer = Tokenizer(nlp.vocab, token_match=re.compile(r'\S+').match)

matcher = DependencyMatcher(nlp.vocab)

# matcher.add("using", [pattern])
dns_str_1 = "cached db.local.clamav.net.cdn.cloudflare.net is 2606:4700::6810:da54"
dns_str_2 = "query[TXT] current.cvd.clamav.net from 172.17.131.81"
dns_str_3 = "forwarded database.clamav.net to 192.168.255.254"
dns_str_4 = "nameserver 127.0.0.1 refused to do a recursive query"
dns_str_5 = "reply shavar.prod.mozaws.net is 52.89.81.52"

str_list = []
str_list.append(dns_str_1)
str_list.append(dns_str_2)
str_list.append(dns_str_3)
str_list.append(dns_str_4)
str_list.append(dns_str_5)

for str in str_list:
    patterns = []
    doc = nlp(dns_str_1)
    if len(doc)> 4:
        continue
    else:
        
        # print out semantic role
        for token in doc:
            print(token.text, token.dep_, token.tag_)
            pattern = [
                {
                    "RIGHT_ID": "anchor_reply",
                    "RIGHT_ATTRS": {"ORTH": "reply"}
                },
                {
                    "LEFT_ID": "anchor_reply",
                    "REL_OP": ">",
                    "RIGHT_ID": "reply_subject",
                    "RIGHT_ATTRS": {"DEP": "nsubj", "OP": "+", "REGEX": {"IN": ["NN", "NNP"]}},
                },
                {
                    "LEFT_ID": "anchor_using",
                    "REL_OP": ">>",
                    "RIGHT_ID": "using_object",
                    "RIGHT_ATTRS": {"DEP": "dobj"},
                },
            ]
            patterns.append(pattern)
        # Add the pattern to the matcher
        matcher.add("dependency_pattern", [pattern])
        matches = matcher(doc)
        print(matches)
        # Each token_id corresponds to one pattern dict
        match_id, token_ids = matches[0]
        for i in range(len(token_ids)):
            print(pattern[i]["RIGHT_ID"] + ":", doc[token_ids[i]].text)
