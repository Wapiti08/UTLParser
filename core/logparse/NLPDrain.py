import regex as re
from pathlib import Path
import pandas as pd
import hashlib
from datetime import datetime
import spacy
import logging

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(messsage)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)

class Node:
    ''' used to save tree mapping for nodes
    
    '''
    def __init__(self, childD=None, depth=0, digitOrtoken=None):
        '''
        :param childD: 
        :param depth:
        :param digitOrtoken: check whether it is number or string type
        '''
        if childD is None:
            childD = dict()
        self.childD = childD
        self.depth = depth
        self.digitOrtoken = digitOrtoken
        

class LogParser:

    def __init__(
            depth,
            st,
    ):
        '''
        :param depth: depth of all leaf nodes
        :param st: similarity threshold
        
        '''
    
    def hasNumbers(self, s):
        return any(char.isdigit() for char in s)
    
    def treeSearch(self, rn, seq):
        '''
        :param rn: root node --- tree type
        :param seq: list of sequences of logmessage
        '''

        # 
    
    def parse(self, logName):
        start_time = datetime.now
        



        logger.info("Parsing done. [Time taken: {!s}]".format(datetime.now() - start_time))




        