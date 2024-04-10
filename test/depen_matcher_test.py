import spacy
from spacy.matcher import DependencyMatcher
from spacy.tokenizer import Tokenizer
import re
from typing import Tuple
from spacy import displacy

nlp = spacy.load("en_core_web_lg")
nlp.tokenizer = Tokenizer(nlp.vocab, token_match=re.compile(r'\S+').match)

matcher = DependencyMatcher(nlp.vocab)

# matcher.add("using", [pattern])
dns_str_3 = "cached db.local.clamav.net.cdn.cloudflare.net is 2606:4700::6810:da54"
dns_str_2 = "query[txt] current.cvd.clamav.net from 172.17.131.81"
dns_str_4 = "forwarded database.clamav.net to 192.168.255.254"
dns_str_1 = "nameserver 127.0.0.1 refused to do a recursive query"
dns_str_5 = "reply shavar.prod.mozaws.net is 52.89.81.52"

str_list = []
str_list.append(dns_str_1)
str_list.append(dns_str_2)
str_list.append(dns_str_3)
str_list.append(dns_str_4)
str_list.append(dns_str_5)

forward_direction = ["reply", 'forward', "cache"]
backward_direction = ["query"]

def verb_ext(doc:spacy.tokens.doc.Doc) -> Tuple[str, str, bool]:
    ''' according to the pos value return the dependency direction
    
    
    '''
    # define all type of verbs
    target_pos_pattern = 'VB.*|VERB$'
    # if there is no AUX adjacent to left of VERB sub -> obj, otherwise obj <- sub
    
    for ord, token in enumerate(doc):
        # add special case for reply
        if token.text == "reply":
            return token.text, token.lemma_, False   
        # check whether there is type 
        if "[" in token.text:
            pattern = r"^(.*?)\["
            match = re.search(pattern, token.text)
            text = match.group(1)
            return text, text, False
        # check whether matching the verb
        elif bool(re.match(target_pos_pattern, token.pos_)):
            # consider passive voice
            if ord - 1>=0:
                if doc[ord-1].pos_ != "AUX":
                    return token.text, token.lemma_, True
                else:
                    return token.text, token.lemma_, True
            # positive voice
            else:
                return token.text, token.lemma_, False


for str in str_list:
    print("parsing log: \n {}".format(str))
    patterns = []
    doc = nlp(dns_str_1)
    # displacy.serve(doc,port=8080)

    # print out semantic role
    for token in doc:
        print(token.text,  token.dep_, token.tag_)
    # get the verb
    verb_text, lemma_text, shift = verb_ext(doc)
    print("Building patterns for anchor {}".format(verb_text))

    if lemma_text in forward_direction:
        print(lemma_text)
        if not shift:
            pattern = [
                {
                    "RIGHT_ID": "anchor_{}".format(verb_text),
                    "RIGHT_ATTRS": {"ORTH": "{}".format(verb_text)}
                },
                # match the domain as subject
                {
                    "LEFT_ID": "anchor_{}".format(verb_text),
                    "REL_OP": "<",
                    "RIGHT_ID": "{}_subject".format(verb_text),
                    # define the potential pos and dep value, and occurrance
                    "RIGHT_ATTRS": {"DEP": "nsubj"},
                },
                # match the ip as object
                {
                    "LEFT_ID": "{}_subject".format(verb_text),
                    "REL_OP": "$++",
                    "RIGHT_ID": "{}_object".format(verb_text),
                    "RIGHT_ATTRS": {"DEP": "attr"},
                },
            ]
            # Add the pattern to the matcher
            matcher.add("{}".format(verb_text.upper()), [pattern])
        else:
            pattern = [
                {
                    "LEFT_ID": "anchor_{}".format(verb_text),
                    "RIGHT_ATTRS": {"ORTH": "{}".format(verb_text)}
                },
                # match the domain as subject
                {
                    "LEFT_ID": "anchor_{}".format(verb_text),
                    "REL_OP": ">",
                    "RIGHT_ID": "{}_subject".format(verb_text),
                    # define the potential pos and dep value, and occurrance
                    "RIGHT_ATTRS": {"DEP": "nsubj"},
                },
                # match the ip as object
                {
                    "LEFT_ID": "anchor_{}".format(verb_text),
                    "REL_OP": ">>",
                    "RIGHT_ID": "{}_object".format(verb_text),
                    "RIGHT_ATTRS": {"DEP": "attr"},
                },
            ]
            # Add the pattern to the matcher
            matcher.add("{}".format(verb_text), [pattern])

    elif lemma_text in backward_direction:
        print(lemma_text)
        pattern = [
                {
                    "RIGHT_ID": "anchor_{}".format(verb_text),
                    "RIGHT_ATTRS": {"ORTH": "{}".format(verb_text)}
                },
                # match the domain as subject
                {
                    "LEFT_ID": "anchor_{}".format(verb_text),
                    "REL_OP": ">",
                    "RIGHT_ID": "{}_object".format(verb_text),
                    # define the potential pos and dep value, and occurrance
                    "RIGHT_ATTRS": {"DEP": "dobj"},
                },
                # match the ip as object
                {
                    "LEFT_ID": "anchor_{}".format(verb_text),
                    "REL_OP": ">>",
                    "RIGHT_ID": "{}_subject".format(verb_text),
                    "RIGHT_ATTRS": {"DEP": "pobj"},
                },
            ]
        # Add the pattern to the matcher
        matcher.add("{}".format(verb_text), [pattern])
    
    else:
        print("Currently, the direction of anchor {} has been not decided".format(verb_text))

    matches = matcher(doc)
    print(matches)
    # Each token_id corresponds to one pattern dict
    match_id, token_ids = matches[0]
    for i in range(len(token_ids)):
        print(pattern[i]["RIGHT_ID"] + ":", doc[token_ids[i]].text)
