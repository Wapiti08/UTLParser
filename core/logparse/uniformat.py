'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-02-16 13:17:40
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-06 11:13:19
 # @ Description: Unifited Module to Generate log format, threshold, depth for General Log Parsing Module
'''

'''
    automatically generate the suitable format for following log parsing

    generate regex:
        domain: \b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b
        ipv4: \b(?:\d{1,3}\.){3}\d{1,3}\b
        ipv4 with port: \b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b
        ipv6: \b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b
        request parameter: \?[^\s]+
    
        
    process format:
        %evt.num %evt.time %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args

'''
import random
import calendar
import re
from pathlib import Path
import logging
import statistics
from utils import util
import statistics

random.seed = 34

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)


short_month_name = calendar.month_abbr[1:]
month_regex = "|".join(short_month_name)
form_month_regex = r"(\b(" + month_regex + r")\b)"

day_regex = r'\b(?:0[1-9]|[12][0-9]|3[01])\b'
timestamp_regex = r'\d{2}:\d{2}:\d{2}'
date_regex=r'\d{4}-\d{2}-\d{2}'

level = "info|warn|error|kernal"

dep_map_dict = {
    "<Month>": ["<Day>"],
    "<Day>":["<Timestamp>"],
    "<Timestamp>":["<Level>", "<Component>", "<Proto>"],
    "<Component>":["<Proto>","<Application>","<Level>"],
    "<Level>":["Proto"],
    "<Proto>": ["[<PID>]", "<Content>",":"],
    ":":["<Content>"],
    "[<PID>]": [":"]
}

pos_com_mapping = {
    0: ["<Month>", "<Date>"],
    1: ["<Day>", "<Timestamp>"],
    2: ["<Timestamp>"],
    3: ["<Component>","<Proto>","<Level>","<Application>"]
}

# component_pool = [
#     "<Timestamp>",
#     "<Day>",
#     "<Month>",
#     "<Date>",
#     "<Content>",
#     "<Level>",
#     "<Component>",
#     "[<PID>]",
#     "<Proto>",'<Application>'
# ]

# remain_chars = [
#     '-','',',','"',"[","]","(",")"
# ]

com_rex_mapping = {
    "<Month>":[form_month_regex],
    "<Day>":[day_regex],
    "<Date>":[date_regex],
    "<Timestamp>": [timestamp_regex],
    "<Component>":[r'^\s*([^ ]+).*'],
    "<Proto>":[r'^.*(?=\[)',r'^.*(?=\:)'],
    "<Application>":[r'^.*?(?=\[|:)'],
    "<Level>":[level],
    "[<PID>]":[r'^\d+$',r'\b\d+\b'],
}


class UniFormat:
    def __init__(self, log_filename: Path):
        with Path(log_filename).open("r") as fr:
            self.logs = fr.readlines()

    def ran_pick(self, num:int):
        ''' randomly pick num logs to generate the log format 
        :param num: default 10
        ''' 
        return random.sample(self.logs, num)

    def com_check(self, sentence:str, pos:int, stop_indictor:str, split_num:int, log_format_dict:dict):
        ''' identify the components according to the regex matching
        :param sentence: single log 
        :param pos: the position or index of potential component, initially 0
        :param stop_indictor: the indictor that splits context with other parts, default :
        :param split_num: how many times to split by indictor, default 1
        :param log_format_dict: the dictionary that saves {pos: component}

        '''
        logger.info("component checking for log format dict")
        # split sentence by first space first
        tokens = sentence.split(" ",split_num)
        log_format_dict[pos] = []
        # only check ending ":"
        if stop_indictor ==":":
            if not tokens[0].endswith(stop_indictor):
                for com_name, regex_list in com_rex_mapping.items():
                    # matched = [re.search(regex, tokens[0]) for regex in regex_list]
                    matched = [re.match(regex, tokens[0]) for regex in regex_list]
                    if any(item is not None for item in matched):
                        log_format_dict[pos].append(com_name)

                if len(log_format_dict[pos]) == 0:
                    return
                else:
                    pos += 1
                    return self.com_check(tokens[1], pos, stop_indictor, split_num, log_format_dict)
                    
            else:
                # check the component of first part
                ## remove the stop indicitor part
                token_no_indicitor = tokens[0].replace(stop_indictor,"")
                print("replacing token from {} to {}".format(tokens[0], token_no_indicitor))
                # add the stop indictor as the middle component
                log_format_dict[pos+1] = [":"]
                # add default second part as the content
                log_format_dict[pos+2] = ["<Content>"]
                for com_name, regex_list in com_rex_mapping.items():
                    matched = [re.search(regex, token_no_indicitor) for regex in regex_list]
                    if any(item is not None for item in matched):
                        # check whether com_name has exsited in pos
                        if com_name in log_format_dict[pos]:
                            continue
                        else:
                            log_format_dict[pos].append(com_name)
                            logger.info("current log format dict is:", log_format_dict)

                if len(log_format_dict[pos]) == 0:
                    return
        else:
            logger.warn("Currently not support stop_indicitor with {}".format(stop_indictor))

        maybe_log_format_dict = log_format_dict
        return maybe_log_format_dict

    def pos_check(self, pos_com_mapping, maybe_log_format_dict):
        ''' reduce noise and build the graph according to neigh_mapping_dict
        
        '''
        logger.info("position checking for log format dict: \n{}".format(maybe_log_format_dict))

        log_format_dict = {}
        # check the position scope
        for pos, com_list in maybe_log_format_dict.items():
            if pos <= (len(pos_com_mapping) - 1):
                maybe_log_format_dict[pos] = list(set(com_list) & set(pos_com_mapping[pos]))
            else:
                break
        
        logger.info("result is: \n {}".format(maybe_log_format_dict))
        log_format_dict = maybe_log_format_dict
        return log_format_dict

    def dep_check(self, dep_map_dict, maybe_log_format_dict):
        # check the dependency pattern
        log_format_dict = {}
        logger.info("dependency checking for log format dict: \n{}".format(maybe_log_format_dict))
        for pos, com_list in maybe_log_format_dict.items():
            if pos != len(maybe_log_format_dict) - 1:
                cur_com = com_list[0]
                if cur_com in dep_map_dict:
                    deps = dep_map_dict[cur_com]
                    # Filter out any incorrect components from the component_list
                    correct_components = [comp for comp in maybe_log_format_dict[pos+1] if comp in deps]
                    # there is right match and not remove
                    if len(correct_components)>0: 
                        if len(correct_components) == maybe_log_format_dict[pos+1]:
                            # Update the component_list with correct components
                            continue
                        # remove wrong prediction then replace with right dependent component
                        else:
                            maybe_log_format_dict[pos+1] = correct_components
                            print(maybe_log_format_dict)
                    
                    # picked wrong component
                    else:
                        continue
                    
        logger.info("result is: \n {}".format(maybe_log_format_dict))
        log_format_dict = maybe_log_format_dict
        return log_format_dict

    def com_rule_check(self, maybe_log_format_dict):
        ''' conduct both depedency and position check
        
        '''
        log_format_dict = {} 
        log_format_dict = self.dep_check(dep_map_dict, maybe_log_format_dict)
        log_format_dict = self.pos_check(pos_com_mapping, log_format_dict)
        for key,value in log_format_dict.items():
            # keep only the first option
            if len(value) >= 2:
                log_format_dict[key] = value[:1]
        return log_format_dict

    def final_format(self, log_format_list:list):
        ''' choose the common path as the most general log format
        :param log_format_list: calculated list of log_format_dict for every choosen logs 
        '''
        # all the same formats, choose any one
        all_dicts_equal = all(d == log_format_list[0] for d in log_format_list)

        if all_dicts_equal:
            return log_format_list[0]
        # different formats choose the longest to increase generality
        else:
            # return max(log_format_list, key=len)
            # return the most common length
            return statistics.mode(map(len, log_format_list))

    def special_space_remove(self, log_format):
        if "[PID]" in log_format:
            # remove the space between PID and previous component
            log_format = re.sub(r'(.*)\s+(\[<PID>\])', r'\1\2', log_format)
            # Replace space between [<PID>] and :
            log_format = re.sub(r'(\[<PID>\])\s+(:)', r'\1\2', log_format)
        else:
            # remove the space between : and previous component
            log_format = re.sub(r'(.*)\s+(:)', r'\1\2', log_format)

        return log_format

    def format_ext(self, log_format_dict:dict):
        ''' shape log format string from dict
        
        '''

        # format the log format to match the log parser
        com_list = list(log_format_dict.values())
        com_list = [com[0] for com in com_list]
        log_format = " ".join(com_list)

        log_format = self.special_space_remove(log_format)

        if "[" in log_format:
            log_format = log_format.replace("[","\[")
            log_format = log_format.replace("]","\]")

        logger.info("Extracted log format is: \n {}".format(log_format))
        return log_format
        
    
    def content_length(self, sentence: str):
        if ":" in sentence:
            tokens = sentence.rsplit(":",1)
        else:
            logger.warn("there is no clear content split indicitor in {}".format(sentence))
            return None
        return len(tokens[1].split(" "))
    
    def cal_depth(self, sens, max_len=10, min_len=3, a=0.5):
        ''' decide the threshold for similarity matching with mean length
        '''
        depth = 0
        token_len_list = []
        occ_list=[]

        for sen in sens:
            len = self.content_length(sen)
            occ = sen.count("=")
            if len:
                token_len_list.append(len)
            if occ:
                occ_list.append(occ)

        # calculate the variance
        len_mean = round(statistics.mean(token_len_list),2)
        if occ_list == []:
            occ_mean = 0
        else:
            occ_mean = round(statistics.mean(occ_list),2)

        if len_mean <= min_len:
            depth = 3
        elif len_mean < max_len:
            depth = 3 + int((1-a)*((max_len - min_len)/ (len_mean - min_len)) + a * occ_mean)
        else:
            depth = 6

        logger.info("calculated depth is: {}".format(depth))
        return depth
    

    def cal_thres(self, sens, max_var=0.28, min_var=0):
        ''' depends on the complexity: the number of = compared with total token number
        calculate the variance of rate of = in sentence, 
        more complex of structure, the lower the similarity threshold
        '''
        threshold = 0
        rate_list = []
        for sen in sens:
            # get the token number
            len = self.content_length(sen)
            # get the total equal mark
            occ = sen.count("=")
            if len:
                rate_list.append(round(occ/len, 3))

        rate_var = statistics.variance(rate_list)  
        if rate_var == min_var:
            threshold = 0.2
        elif rate_var < max_var:
            threshold = 0.2 + round(rate_var * (0.6) / (max_var - min_var),3)
        else:
            threshold = 0.8
        
        logger.info("calculated threshold is: {}".format(threshold))
        return threshold
            
