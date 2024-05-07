'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-01-31 15:23:57
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-06 11:11:30
 # @ Description: General Logs Parsing Module
 '''

'''
    combine log parser, regex, semantic parser with dependency to build 
    causal graphs among subject, action, object

    log parser: parse template and variables
    regex: match ip or domain
    iocs: common malicious indicitors
    list of synonyms for actions: action used to define the direction between entities
    semantic paser: extract the dependency between tokens --- used to decide the relations 

'''

import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
import regex as re
from pathlib import Path
import pandas as pd
import hashlib
from datetime import datetime
import spacy
import logging
from tqdm import tqdm
from utils import util
from core.logparse.semdep import DepParse
import spacy
import yaml
from core.pattern import domaininfo
import config
from spacy.tokenizer import Tokenizer

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)
nlp = spacy.load("en_core_web_lg")
nlp.tokenizer = Tokenizer(nlp.vocab, token_match=re.compile(r'\S+').match)


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
        

class GenLogParser:

    def __init__(self,
            depth=4,
            st=0.4,
            rex = [],
            indir="./",
            outdir="../../data/result/",
            log_format="",
            log_name="",
            maxChild=100,
            keep_para=True,
    ):
        '''
        :param depth: depth of all leaf nodes
        :param st: similarity threshold
        :param rex: regular regex to match explicit variables/indicitors
        :param maxChild: the max number of child of an internal node
        :param poi_list: timestamp, Parameters
        '''

        self.st = st
        self.depth = depth
        self.rex = rex
        self.logName = log_name
        self.path = indir
        self.maxChild = maxChild
        self.savePath = outdir
        self.log_format = log_format
        self.keep_para = keep_para

        self.format_output = {
            "Time":[],
            "Src_IP":[],
            "Dest_IP":[],
            "Proto":[],
            "Domain":[],
            "Parameters":[],
            "IOCs":[],
            "PID":[],
            "Actions":[],
            "Status":[],
            "Direction":[],
            "Label":[]
        }

        self.depparser = DepParse(log_name.split(".")[0])

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
            curSim, curNumOfPara = self.seqDist(logClust.logTemplate, seq)
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
            Path(self.path).joinpath(self.logName), regex, headers
        )

    def preprocess(self, line):
        ''' match the explicit variables or indicitor as the <*>
        including ip, domain, path ...
        '''
        for var_reg in self.rex:
            line = re.sub(var_reg , "<*>", line)
        return line

    def gen_logformat_regex(self, logformat):
        ''' based on given logformat to generate the regex that matches the corresponding components
        :param logformat: given format components ---- based on specific log format
        one example would be: "<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>",

        '''

        return util.gen_regex_from_logformat(logformat)

    def log_to_dataframe(self, log_file: Path, regex, headers):
        ''' write raw log to pandas dataframe, with list and headers
        
        '''
        log_messages = []
        lcount = 0

        with log_file.open('r') as fr:
            data = fr.readlines()
            for line in data:
                try:
                    match = regex.search(line.strip())
                    message = [match.group(header) for header in headers]
                    log_messages.append(message)
                    lcount += 1
                except Exception as e:
                    logger.warning("Skip line: %s", line)

        logdf = pd.DataFrame(log_messages, columns = headers)
        logdf.insert(0, "LineId", None)
        logdf["LineId"] = logdf.index + 1
        print("Total lines: ", len(logdf))
        logger.info("The parsing rate is: {:.2%}".format(len(logdf) / len(data) ))
        return logdf


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
            logID = line["LineId"]
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
        self.outputResult(logCluL)

        logger.info("Parsing done. [Time taken: {!s}]".format(datetime.now() - start_time))


    def outputResult(self, logClustL):
        log_templates = [0] * self.df_log.shape[0]
        log_templateids = [0] * self.df_log.shape[0]
        df_events = []
        for logClust in logClustL:
            template_str = " ".join(logClust.logTemplate)
            occurrence = len(logClust.logIDL)
            template_id = hashlib.md5(template_str.encode("utf-8")).hexdigest()[0:8]
            for logID in logClust.logIDL:
                logID -= 1
                log_templates[logID] = template_str
                log_templateids[logID] = template_id
            df_events.append([template_id, template_str, occurrence])

        df_event = pd.DataFrame(
            df_events, columns=["EventId", "EventTemplate", "Occurrences"]
        )
        self.df_log["EventId"] = log_templateids
        self.df_log["EventTemplate"] = log_templates
        if self.keep_para:
            self.df_log["Parameters"] = self.df_log.apply(
                self.get_parameter_list, axis=1
            )
        self.df_log.to_csv(
            Path(self.savePath).joinpath(self.logName + "_structured.csv"), index=False
        )

        occ_dict = dict(self.df_log["EventTemplate"].value_counts())
        df_event = pd.DataFrame()
        df_event["EventTemplate"] = self.df_log["EventTemplate"].unique()
        df_event["EventId"] = df_event["EventTemplate"].map(
            lambda x: hashlib.md5(x.encode("utf-8")).hexdigest()[0:8]
        )
        df_event["Occurrences"] = df_event["EventTemplate"].map(occ_dict)
        df_event.to_csv(
            Path(self.savePath).joinpath(self.logName + "_templates.csv"),
            index=False,
            columns=["EventId", "EventTemplate", "Occurrences"],
        )


    def get_parameter_list(self, row):
        template_regex = re.sub(r"<.{1,5}>", "<*>", row["EventTemplate"])
        if "<*>" not in template_regex:
            return []
        template_regex = re.sub(r"([^A-Za-z0-9])", r"\\\1", template_regex)
        template_regex = re.sub(r"\\ +", r"\\s+", template_regex)
        template_regex = "^" + template_regex.replace("\<\*\>", "(.*?)") + "$"
        parameter_list = re.findall(template_regex, row["Content"])
        parameter_list = parameter_list[0] if parameter_list else ()
        parameter_list = (
            list(parameter_list)
            if isinstance(parameter_list, tuple)
            else [parameter_list]
        )

        return parameter_list

    def para_check(self, para_part: list):
        ''' remain only parameters like path/domain/ip/username ...
        
        '''
        new_paras = []

        for element in para_part:
            if element != '':
                ip_match = util.ip_match(element)
                if ip_match:
                    new_paras.extend(ip_match)
                    continue
                if "/" in element or "\\" in element:
                    path_match = util.path_match(element)
                    if path_match:
                        # check the type of element --- avoid tuples as values
                        if isinstance(path_match[0], str):
                            # avoid repetitions
                            new_paras.extend(list(set(path_match)))
                        elif isinstance(path_match[0], tuple):
                            new_paras.extend(list(set(element for tup in path_match for element in tup)))
                        continue
                # match domain
                domain_match = util.domain_match(element)
                if domain_match:
                    new_paras.extend(domain_match)
                    continue
                # match potential user or group names
                if not element.isdigit():
                    new_paras.append(element)
                    continue

        # check potential split commands
        new_paras = util.split_commands_check(new_paras)
        return new_paras

    def action_ext(self, content_part: str):
        ''' extract the potential anchor word, waiting to add more rules on direction
        
        '''
        # if ":" in content_part:
        #     content_part = content_part.rsplit(":")[1]
        # define the extract verb
        clean_content = util.token_filter(content_part)
        doc = nlp(clean_content)
        # for token in doc:
        #     print(token.text)
        #     print(token.pos_)
        #     print(token.dep_)
        #     print(token.tag_)
        # check available verb with basic rule
        veb_res = self.depparser.verb_ext(doc)
        if veb_res:        
            # print(veb_res)
            return veb_res[0], veb_res[1]
        
        # check pre-define dependency pattern
        dep_res = self.depparser.depen_parse(doc)
        if dep_res:
            # print(dep_res)
            return dep_res[0], dep_res[1]
        

        return '-', '-'

    def time_create(self, log_df: pd.DataFrame):
        ''' assemble the separate time  component to unified format
        
        '''
        log_df = util.time_format(log_df)
        return log_df["Time"]

    def poi_ext(self,):
        ''' extract the potential action from content
        
        '''
        tqdm.pandas(desc="extracting pois")
        self.df_log[["Content", "Direction"]] = self.df_log["Content"].apply(lambda x: pd.Series(self.action_ext(x)))
        # filter points of interests
        self.df_log["Parameters"] = self.df_log["Parameters"].apply(lambda x: self.para_check(x))
        self.df_log['Time'] = self.time_create(self.df_log)


    def get_output(self, label: int):
        ''' import extracted data to unified output format:
            Time, Src_IP, Dest_IP, Proto, Domain, Parameters, IOCs, Actions, Status, Direction
        :param label: label information is given based on whether reading malicious log records
        '''
        start_time = datetime.now() 
        log_num = len(self.df_log)
        # for general logs, only extract time, parameters, actions
        column_poi_map = domaininfo.unstru_log_poi_map["general"]

        for column, _ in self.format_output.items():
            if column in ["Time", "Parameters", "Direction", "PID", "Src_IP", "Proto"]:
                if column in self.df_log.columns:
                    self.format_output[column] = self.df_log[column].tolist()
                else:
                    self.format_output[column] = ["-"] * log_num
            elif column == "Actions":
                self.format_output[column] = self.df_log[column_poi_map[column]].tolist()
            elif column == "Label":
                self.format_output[column] = [label] * log_num
            else:
                self.format_output[column] = ["-"] * log_num

        # logger.info("the parsing output is like: {}".format(self.format_output))

        pd.DataFrame(self.format_output).to_csv(
            Path(self.savePath).joinpath(self.logName + "_uniform.csv"), index=False
        )
        
        # pd.DataFrame(self.format_output).to_parquet(
        #     Path(self.savePath).joinpath(self.logName + "_uniform.parquet"), index=False
        # )

        logger.info("Unified Output is Done. [Time taken: {!s}]".format(datetime.now() - start_time))
