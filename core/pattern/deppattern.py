


# define general pattern to match common sentence with clear subject, action, object
# for example: fileA access fileB

class DepPatterns:
    def __init__(self, anchor):
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
        
