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
    
    def __init__(self, log_type:str):
        self.log_type = log_type
    
    def default_dep_pattern(self, ):
        ''' define specific dependency patterns for dns logs --- limited verbs
        
        '''
        if "dns" in self.log_type.lower():
            anchors = []
            patterns = []
            for anchor in ["cached", "reply","forwarded", "query"]:
                if anchor in ["cached", "reply"]:
                    anchors.append(anchor)
                    patterns.append([
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
                            "RIGHT_ATTRS": {"DEP": {"IN":["nummod","nsubj"]}},
                        },
                        # match the ip as object
                        {
                            "LEFT_ID": "{}_subject".format(anchor),
                            "REL_OP": "$++",
                            "RIGHT_ID": "{}_object".format(anchor),
                            "RIGHT_ATTRS": {"DEP": "attr"},
                        },
                    ])
                elif anchor == "forwarded":
                    anchors.append(anchor)
                    patterns.append([
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
                    ])
                elif anchor == "query":
                    anchors.append(anchor)
                    patterns.append([
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
                            "RIGHT_ATTRS": {"DEP":{"IN":["dobj","nmod"]}},
                        },
                        # match the ip as object
                        {
                            "LEFT_ID": "anchor_{}".format(anchor),
                            "REL_OP": ">>",
                            "RIGHT_ID": "{}_subject".format(anchor),
                            "RIGHT_ATTRS": {"DEP": "pobj"},
                        },
                    ])
                
            return anchors, patterns
        
        else:
            # print("there is no pre-defined dependency patterns for {}".format(self.log_type))
            return None
