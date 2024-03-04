""" 
@Description: Defined Patterns for Dependency Parsing
@Author: newt.tan 
@Date: 2024-02-29 09:34:51 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-02-29 09:34:51  
"""


# define general pattern to match common sentence with clear subject, action, object
# for example: fileA access fileB

class DepPatterns:
    def __init__(self, log_type:str, anchor: str):
        if log_type.upper() == "DNS":
            return self.dns_pattern(anchor.lower())
        
    
    def dns_pattern(self):
        verb_text="cached" or "reply"
        dns_cache_pattern = [
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
        verb_text = "forwarded"
        dns_forward_pattern = [
            {
                "RIGHT_ID": "anchor_{}".format(verb_text),
                "RIGHT_ATTRS": {"ORTH": "{}".format(verb_text)}
            },
            # match the domain as subject
            {
                "LEFT_ID": "anchor_{}".format(verb_text),
                "REL_OP": ">",
                "RIGHT_ID": "{}_subject".format(verb_text),
                # define the potential pos and dep value, and occurrance
                "RIGHT_ATTRS": {"DEP": "dobj"},
            },
            # match the ip as object
            {
                "LEFT_ID": "anchor_{}".format(verb_text),
                "REL_OP": ">>",
                "RIGHT_ID": "{}_object".format(verb_text),
                "RIGHT_ATTRS": {"DEP": "pobj"},
            },
        ]
        verb_text="query"
        dns_query_pattern = [
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
        
