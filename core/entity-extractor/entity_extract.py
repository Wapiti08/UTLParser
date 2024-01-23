""" 
@Description: module to extract subject, object, action from unstructured logs
@Author: newt.tan 
@Date: 2024-01-23 14:58:04 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-01-23 14:58:04  
"""

import spacy
import yaml
from pathlib import Path

config_file = Path.cwd().parent.parent.joinpath("config.yaml")
config = yaml.safe_load(config_file)

nlp = spacy.load('en_core_web_lg')

# defined the potential pos for subjects
SUBJECTS = {"nsubj", "nsubjpass", "csubj", "csubjpass", "agent", "expl"}

# defined the potential pos for objects
OBJECTS = {"dobj", "dative", "attr", "oprd","pobj"}

# defined the potential pos to break adjoining items
BREAKER_POS = {"CCONJ", "VERB"}

# defined the works that are negative
NEGATIONS = {"no", "not", "n't", "never", "none"}

# check dependency set based on parsed poc tags
def contains_conj(depSet):
    conj_set = config['conj_set']
    if set(conj_set) & set(depSet):
        return True
    else:
        return False



