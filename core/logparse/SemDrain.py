'''
    combine log parser, regex, semantic parser with dependency to build 
    causal graphs among subject, action, object

    log parser: parse template and variables
    regex: match ip or domain
    iocs: common malicious indicitors
    list of synonyms for actions: action used to define the direction between entities
    semantic paser: extract the dependency between tokens --- used to decide the relations 

'''


import regex as re
from pathlib import Path
import pandas as pd
import hashlib
from datetime import datetime
import spacy
import logging
from tqdm import tqdm

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
        :param childD: a dictionary with index and corresponding token
        :param depth: 
        :param digitOrtoken: number of token string (first layer) or token itself (second layer)
        
        description: 
            the first layer is the length, the following layers are the tokens in tree structure
        '''
        if childD is None:
            childD = dict()
        self.childD = childD
        self.depth = depth
        self.digitOrtoken = digitOrtoken
        

class LogParser:

    def __init__(self,
            depth=4,
            st=0.4,
            rex = [],
            indir="./",
            outdir="../../data/result/",
            log_format="",
            maxChild=100,
            filter=0,
            key=0,
    ):
        '''
        :param depth: depth of all leaf nodes
        :param st: similarity threshold
        :param rex: regular regex to match explicit variables/indicitors
        :param maxChild: the max number of child of an internal node
        :param filter: bool type: whether has specific filter schema for regex matching
        :param key: bool type: whehther following key value pair 
        '''

        self.st = st
        self.depth = depth
        self.rex = rex
        self.logName = None
        self.path = indir
        self.maxChild = maxChild
        self.savePath = outdir
        self.log_format = log_format
        self.filter = filter
        self.key = key

    def hasNumbers(self, s):
        return any(char.isdigit() for char in s)
    
    def treeSearch(self, rn: Node, seq:list):
        '''
        :param rn: root node --- Node type
        :param seq: list of sequences of logmessage
        '''

        # define return cluster if found 
        retLogClust = None
        
        seqLen = len(seq)
        if seqLen not in rn.childD:
            return retLogClust
        # check the second layer with parent tokens
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
        
    def fastMatch(self, logClustL:[Logcluster], seq): # type: ignore
        ''' find the corresponding event template from sequence
        :param logClustL: 
        :param seq: list of tokens in sequential log
        '''
        retLogClust = None
        maxSim = -1
        maxNumOfPara = -1
        maxClust = None

        for logClust in logClustL:
            curSim, curNumOfPara = self.seqDist(logClust.template, seq)
            if curSim > maxSim or (curSim == maxSim and curNumOfPara > maxNumOfPara):
                maxSim = curSim
                maxNumOfPara = curNumOfPara
                maxClust = logClust

        # compare with threshold   
        if maxSim >= self.st: 
            retLogClust = maxClust
        
        return retLogClust


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
    
    def addSeqToPrefixTree(self, rn: Node, logClust: Logcluster):
        ''' add sequence to pre-defined tree according to template
        
        '''
        seqLen = len(logClust.logTemplate)
        # check the first layer with token length
        if seqLen not in rn.childD:
            firstLayer = Node(depth=1, digitOrtoken=seqLen)
            rn.childD[seqLen] = firstLayer
        else:
            firstLayer = rn.childD[seqLen]
        # fill the node tree based on template
        parentn = firstLayer

        currentDepth = 1

        for token in logClust.logTemplate:
            # add current log cluster to the leaf node when reaching limitation
            if currentDepth >= self.depth or currentDepth > seqLen:
                if len(parentn.childD) == 0:
                    parentn.childD = [logClust]
                else:
                    parentn.childD.append(logClust)
                break

            # if token not matched in this layer of existing tree
            if token not in parentn.childD:
                # check whether digit exists in token
                if not self.hasNumbers(token):            
                    # check <*> exists in tree
                    if "<*>" in parentn.childD:
                        # check whether length of childD is larger then maxChild
                        if len(parentn.childD) < self.maxChild:
                            newNode = Node(depth=currentDepth, digitOrtoken=token)
                            parentn.childD[token] = newNode
                            parentn = newNode
                        else:
                            parentn = parentn.childD["<*>"]
                    else:
                    # create new node and append as child node
                        # check maxchild limiation
                        if len(parentn.childD) + 1 < self.maxChild:
                            newNode = Node(depth=currentDepth+1, digitOrtoken=token)
                            parentn.childD[token] = newNode
                            parentn = newNode
                        elif len(parentn.childD) + 1 == self.maxChild:
                            newNode = Node(depth=currentDepth+1, digitOrtoken="<*>")
                            parentn.childD["<*>"] = newNode
                        else:
                            parentn = parentn.childD["<*>"]

                # check <*> exists in tree
                else:
                    if "<*>" not in parentn.childD:
                        newNode = Node(depth=currentDepth + 1, digitOrtoken="<*>")
                        parentn.childD["<*>"] = newNode
                        parentn = newNode
                    else:
                        parentn = parentn.childD["<*>"]

            # if matched
            else:
                parentn = parentn.childD[token]
            
            currentDepth += 1

    def load_data(self):
        ''' generate the headers (pandas dataframe) and regex (used for parse logs into components) 
        
        '''
        headers, regex = self.gen_logformat_regex(self.log_format)
        self.df_log = self.log_to_dataframe(
            Path.joinpath(self.path, self.logName), regex, headers
        )

    def preprocess(self):
        ''' match the explicit variables or indicitor as the <*>
        including ip, domain, path ...
        '''
        for var_reg in self.rex:
            line = re.sub(var_reg , "<*>", line)
        return line

    def log_to_dataframe(self, log_file: Path, regex, headers):
        ''' write raw log to pandas dataframe, with list and headers
        
        '''
        log_messages = []
        lcount = 0
        with log_file.open('r') as fr:
            for line in fr.readlines():
                try:
                    match = regex.search(line.strip())
                    message = [match.group(header) for header in headers]
                    log_messages.append(message)
                    lcount += 1
                except Exception as e:
                    logger.warning("Skip line: %s", line)
        logdf = pd.DataFrame(log_messages, columns = headers)
        logdf.insert(0, "LineId", None)
        logdf["LineId"] = [i + 1 for i in range(lcount)]
        print("Total lines: ", len(logdf))
        return logdf

    def gen_logformat_regex(self, logformat):
        ''' based on given logformat to generate the regex that matches the corresponding components
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
    
    def getTemplate(self, seq1, seq2):
        ''' get event template by matching wildcard and tokens
        
        '''
        assert len(seq1) == len(seq2)
        retVal = []

        for i, token in enumerate(seq1):
            if token == seq2[i]:
                retVal.append(token)
            else:
                retVal.append("<*>")
        
        return retVal

    def addSeqToPrefixTree(self, rn: Node, logClust: Logcluster):
        ''' 
        :param rn: the Node struct
        :param logClust: the class of log cluster
        '''
        seqLen = len(logClust)
        if seqLen not in rn.childD:
            firLayerNode = Node(depth=1, digitOrtoken=seqLen)
            rn.childD[seqLen] = firLayerNode
        else:
            firLayerNode = rn.childD[seqLen]
        

    def parse(self, logName):
        # define the parsing file path
        print("Parsing file: " + Path(self.path).joinpath(logName).as_posix())
        start_time = datetime.now()
        self.logName = logName
        rootNode = Node()
        logCluL = []

        # load data
        self.load_data()

        # process line by line
        for idx, line in tqdm(self.df_log.iterrows(), desc="Processing log lines"):
            # treesearch the logcluster of line
            logID = line["LineID"]
            logmessageL = self.preprocess(line["Content"]).strip().split()
            matchCluster = self.treeSearch(rootNode, logmessageL)

            # not exist, create a new cluster
            if matchCluster is None:
                newCluster = Logcluster(logTemplate=logmessageL, logIDL=[logID])
                logCluL.append(newCluster)
                self.addSeqToPrefixTree(rootNode, newCluster)

            # add new log message to existing cluster
            else:
                newTemplate = self.getTemplate(logmessageL, matchCluster.logTemplate)
                matchCluster.logIDL.append(logID)
                # check whether totally matched, otherwise create a new template
                if " ".join(newTemplate) != " ".join(matchCluster.logTemplate):
                    matchCluster.logTemplate = newTemplate

        # define savepath
        if not Path(self.savePath).exists():
            Path(self.savePath).mkdir(parents=True, exist_ok=True)

        # output result
        self.outputResut(logCluL)

        logger.info("Parsing done. [Time taken: {!s}]".format(datetime.now() - start_time))


    def outputResult(self, logClustL):
        print(logClustL)

        