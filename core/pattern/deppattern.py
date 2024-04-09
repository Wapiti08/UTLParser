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
        
    
    def dns_pattern(self, anchor: str):
        if anchor in ["cache", "reply"]:
            dns_pattern = [
                {
                    "RIGHT_ID": "anchor_{}".format(anchor),
                    "RIGHT_ATTRS": {"ORTH": "{}".format(anchor)}
                },
                # match the domain as subject
                {
                    "LEFT_ID": "anchor_{}".format(anchor),
                    "REL_OP": "<",
                    "RIGHT_ID": "{}_subject".format(anchor),
                    # define the potential pos and dep value, and occurrance
                    "RIGHT_ATTRS": {"DEP": "nsubj"},
                },
                # match the ip as object
                {
                    "LEFT_ID": "{}_subject".format(anchor),
                    "REL_OP": "$++",
                    "RIGHT_ID": "{}_object".format(anchor),
                    "RIGHT_ATTRS": {"DEP": "attr"},
                },
            ]
        elif anchor == "forward":
            dns_pattern = [
                {
                    "RIGHT_ID": "anchor_{}".format(anchor),
                    "RIGHT_ATTRS": {"ORTH": "{}".format(anchor)}
                },
                # match the domain as subject
                {
                    "LEFT_ID": "anchor_{}".format(anchor),
                    "REL_OP": ">",
                    "RIGHT_ID": "{}_subject".format(anchor),
                    # define the potential pos and dep value, and occurrance
                    "RIGHT_ATTRS": {"DEP": "dobj"},
                },
                # match the ip as object
                {
                    "LEFT_ID": "anchor_{}".format(anchor),
                    "REL_OP": ">>",
                    "RIGHT_ID": "{}_object".format(anchor),
                    "RIGHT_ATTRS": {"DEP": "pobj"},
                },
            ]
        elif anchor == "query":
            dns_pattern = [
                    {
                        "RIGHT_ID": "anchor_{}".format(anchor),
                        "RIGHT_ATTRS": {"ORTH": "{}".format(anchor)}
                    },
                    # match the domain as subject
                    {
                        "LEFT_ID": "anchor_{}".format(anchor),
                        "REL_OP": ">",
                        "RIGHT_ID": "{}_object".format(anchor),
                        # define the potential pos and dep value, and occurrance
                        "RIGHT_ATTRS": {"DEP": "dobj"},
                    },
                    # match the ip as object
                    {
                        "LEFT_ID": "anchor_{}".format(anchor),
                        "REL_OP": ">>",
                        "RIGHT_ID": "{}_subject".format(anchor),
                        "RIGHT_ATTRS": {"DEP": "pobj"},
                    },
                ]
            
