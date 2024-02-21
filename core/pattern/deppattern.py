


# define general pattern to match common sentence with clear subject, action, object
# for example: fileA access fileB

class DepPatterns:
    def __init__(self, anchor):
        im_dep_pattern = [
            # define the anchor token
            {
                # unique id
                "RIGHT_ID": "anchor_{}".format(anchor),
                "RIGHT_ATTRS": {"ORTH": anchor},
            },
            # define the rule for matching subject
            {
                "LEFT_ID": "anchor_{}".format(anchor),
                "REL_OP": ">",
                "RIGHT_ID": "{}_subject".format(anchor),
                # nominal subject
                "RIGHT_ATTRS": {"DEP": "nsubj"},
            },
            # define the rule for matching object
            {
                "LEFT_ID": "anchor_{}".format(anchor),
                "REL_OP": ">",
                "RIGHT_ID": "{}_object".format(anchor),
                # direct object
                "RIGHT_ATTRS": {"DEP": "dobj"},
            }
        ]
        
        ch_dep_pattern = [
            # define the anchor token
            {
                # unique id
                "RIGHT_ID": "anchor_{}".format(anchor),
                "RIGHT_ATTRS": {"ORTH": anchor},
            },
            # define the rule for matching subject
            {
                "LEFT_ID": "anchor_{}".format(anchor),
                "REL_OP": ">>",
                "RIGHT_ID": "{}_subject".format(anchor),
                # nominal subject
                "RIGHT_ATTRS": {"DEP": "nsubj"},
            },
            # define the rule for matching object
            {
                "LEFT_ID": "anchor_{}".format(anchor),
                "REL_OP": ">>",
                "RIGHT_ID": "{}_object".format(anchor),
                # direct object
                "RIGHT_ATTRS": {"DEP": "dobj"},
            }
        ]