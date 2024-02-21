import spacy
from spacy.matcher import DependencyMatcher

nlp = spacy.load("en_core_web_lg")
matcher = DependencyMatcher(nlp.vocab)

# pattern = [
#     {
#         "RIGHT_ID": "anchor_using",
#         "RIGHT_ATTRS": {"ORTH": "founded"}
#     },
#     {
#         "LEFT_ID": "anchor_using",
#         "REL_OP": ">>",
#         "RIGHT_ID": "using_subject",
#         "RIGHT_ATTRS": {"DEP": "nsubj"},
#     },
#     {
#         "LEFT_ID": "anchor_using",
#         "REL_OP": ">>",
#         "RIGHT_ID": "using_object",
#         "RIGHT_ATTRS": {"DEP": "dobj"},
#     },
# ]

pattern = [
    {
        "RIGHT_ID": "object",
        "RIGHT_ATTRS": {"LEMMA": "nameserver"}
    },
    {
        "LEFT_ID": "object",
        "REL_OP": "<",
        "RIGHT_ID": "subject",
        "RIGHT_ATTRS": {"LEMMA": "domain"}
    }
]

# Add the pattern to the matcher
matcher.add("dependency_pattern", [pattern])

# matcher.add("using", [pattern])
doc = nlp("using nameserver 127.0.0.1#53 for domain 228.131.168.192.in-addr.arpa")
matches = matcher(doc)

print(matches)
# Each token_id corresponds to one pattern dict
match_id, token_ids = matches[0]
for i in range(len(token_ids)):
    print(pattern[i]["RIGHT_ID"] + ":", doc[token_ids[i]].text)
