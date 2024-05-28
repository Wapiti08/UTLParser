""" 
@Description: define function to filter / santize tokens, sentences
@Date: 2024-02-29 10:07:10 
@Last Modified time: 2024-02-29 10:07:10  
"""

import re

bucket_patterns = [
   r'\[.*?\]',
   r'\(.*?\)'
]


def sani_token(sen:str, patterns:list) -> str:
    ''' process special cases including:
    compound token: [], ()
    
    '''
    # check whether any special 
    if "[" in sen or "(" in sen:
        for pattern in bucket_patterns:
            sani_sen = re.sub(pattern, '', sen)


    return sani_sen       

