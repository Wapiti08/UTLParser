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


class Logcluster:
    def __init__(self, logTemplate="", logIDL=None):
        self.logTemplate = logTemplate
        if logIDL is None:
            logIDL = []
        self.logIDL = logIDL


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
    
    def treeSearch(self, rn: Node, seq):
        '''
        :param rn: root node --- Node type
        :param seq: list of sequences of logmessage
        '''

        # define return cluster if found 
        retLogClust = None
        
        seqLen = len(seq)
        if seqLen not in rn.childD:
            return retLogClust

        parentn = rn.childD[seqLen]

        currentDepth = 1
        for token in seq:
            # reach the depth limiation, exit
            if currentDepth >= self.depth or currentDepth > seqLen:
                break    
            # traverse from top to down
            if token in parentn.childD:
                parentn = parentn.childD[token]
            elif "<*>" in parentn.childD:
                parentn = parentn.childD["<*>"]
            else:
                return retLogClust

            currentDepth += 1
        # return the dictionary of parent/child
        logClustL = parentn.childD
        retLogClust = self.fastMatch(logClustL, seq)

        return retLogClust
        
    def fastMatch(self, logClustL:[Logcluster], seq):
        '''
        :param logClustL: 
        :param seq: list of tokens in sequential log
        '''
        retLogClust = None

        


    def seqDist(self, seq1, seq2):
        ''' calculate the similarity rate and extract number of parameter
        
        '''

        assert len(seq1) == len(seq2)
        simTokens = 0
        numOfPar = 0

        for token1, token2 in zip(seq1, seq2):
            if token1 == token2:
                simTokens += 1
            if token1 == "<*>":
                numOfPar += 1
                continue

        return float(simTokens)/len(seq1), numOfPar
    


    def parse(self, logName):
        print("Parsing file: " + Path(self.path).joinpath(logName))
        start_time = datetime.now
        self.logName = logName
        rootNode = Node()
        logCluL = []

        logger.info("Parsing done. [Time taken: {!s}]".format(datetime.now() - start_time))


    def load_data(self):
    

    def log_to_dataframe(self,):

    
    def gen_logformat_regex(self, logformat):
        '''
        :param logformat: given format components ---- based on specific log format
        one example would be: "<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>",

        '''
        headers = []
        # match any context inside <> without < and > themselves
        splitters = re.split(r"(<[^<>]+>)", logformat)
        regex = ""
        for k in range(len(splitters)):
            if k % 2 == 0:
                # process the space between adjacent components
                splitter = re.sub(" +", "\\\s+", splitters[k])
                regex += splitter
            else:
                header = splitters[k].strip("<").strip(">")
                # create a named capture group
                regex += "(?P<%s>.*)" % header
                headers.append(header)
        regex = re.compile("^" + regex + "$")
        return headers, regex
    


        