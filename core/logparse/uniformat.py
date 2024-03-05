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
import spacy
import nltk
import flair
import random
import calendar
import re
from pathlib import Path
import logging

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

level = "info|warn|error"

dep_map_dict = {
    "<Month>": ["<Day>"],
    "<Day>":["<Timestamp>"],
    "<Timestamp>":["<Level>", "<Component>", "<Proto>"],
    "<Component>":["<Proto>","<Application>"],
    ":":["<Content>"],
    "<Proto>": ["[<PID>]", "<Content>",":"],
    "[<PID>]": [":"]
}

pos_com_mapping = {
    0: ["<Month>", "<Date>"],
    1: ["<Day>", "<Timestamp>"],
    2: ["<Timestamp>"],
    3: ["<Component>","<Proto>","<Level>","<Application>"]
}

component_pool = [
    "<Timestamp>",
    "<Day>",
    "<Month>",
    "<Date>",
    "<Content>",
    "<Level>",
    "<Component>",
    "[<PID>]",
    "<Proto>",'<Application>'
]

remain_chars = [
    '-','',',','"',"[","]","(",")"
]

com_rex_mapping = {
    "<Month>":[form_month_regex],
    "<Day>":[day_regex],
    "<Date>":[date_regex],
    "<Timestamp>": [timestamp_regex],
    "<Component>":[r'^\s*([^ ]+).*'],
    "<Proto>":[r'^.*?(?=\[|:)'],
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

        ''' 
        return random.sample(self.logs, num)

    def com_check(self, sentence:str, pos:int, stop_indictor:str, split_num:int, log_format_dict:dict):
        ''' identify the components according to the regex matching
        
        '''
        # split sentence by first space first
        tokens = sentence.split(" ",split_num)
        log_format_dict[pos] = []
        # only check ending ":"
        if stop_indictor ==":":
            if not tokens[0].endswith(stop_indictor):
                for com_name, regex_list in com_rex_mapping.items():
                    matched = [re.search(regex, tokens[0]) for regex in regex_list]
                    print(matched)
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
                            print("current log format dict is:", log_format_dict)

                if len(log_format_dict[pos]) == 0:
                    return
        else:
            print("Currently not support stop_indicitor with {}".format(stop_indictor))

        return log_format_dict

    def pos_check(self, pos_com_mapping, maybe_log_format_dict):
        ''' reduce noise and build the graph according to neigh_mapping_dict
        
        '''
        log_format_dict = {}
        # check the position scope
        for pos, com_list in maybe_log_format_dict.items():
            if pos <= (len(pos_com_mapping) - 1):
                maybe_log_format_dict[pos] = list(set(com_list) & set(pos_com_mapping[pos]))
            else:
                break

        log_format_dict = maybe_log_format_dict
        return log_format_dict

    def dep_check(self, dep_map_dict, maybe_log_format_dict):
        # check the dependency pattern
        log_format_dict = {}
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
                    # picked wrong component
                    else:
                        return
                    

        log_format_dict = maybe_log_format_dict
        return log_format_dict

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
        ''' extract log format
        
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
        
    def final_format(self, log_format_list:list):
        # choose the shorted path as the most general log format
        if len(log_format_list) == 1:
            return log_format_list[0]
        # all the same formats, choose any one
        elif len(set(log_format_list)) == 1:
            return log_format_list[0]
        # different formats:
        else:
            pass
    
    def cal_st(self):
        '''
        
        '''
    
    def cal_depth(self):
        '''
        
        '''

        
# the matching format for unstructured logs
# format_dict = {
#     "DNS": {
#         "dnsmasq": {
#             "log_format": "<Month> <Date> <Time> dnsmasq\[<PID>\]: <Content>",
#             # match the domain, ipv4 and ipv6
#             "regex": [r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", r"\b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"],
#             "st":0.7,
#             "depth":4,
#             # filter for domain name match with general domain extension
#             "filter": 1,
#             "iocs":0,
#         },
#     },
#     "Apache": {
#         "org-access": {
#             # "log_format": "<SRC_IP> - - \[<Time>\] \"<Request_Method> <Content> <HTTP_Version>\" <Status_Code> <Response_Size> \"<Referer>\" \"<User_Agent>\"",
#             "log_format": "<SRC_IP> - - \[<Time>\] \"<Request_Method> <Content> <HTTP_Version>\" <Status_Code> <Response_Size> \"<Referer>\" \"<User_Agent>\"",
#             # match the parameter part
#             "regex": [r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r"\?[^\s]+"],
#             "st": 0.8,
#             "depth": 5,
#             "filter":0,
#             "iocs":0,
#         },
#         "audit": {
#             # "log_format": "type=<Type> msg=audit\(<Time>\): pid=<PID> uid=<UID> auid=<AUID> ses=<SES> msg=\'unit=<Unit> comm=<Comm> exe=<Exe> hostname=<HostName> addr=<Addr> terminal=<Terminal> res=<Res>\'",
#             # "log_format": "type=<Type> msg=audit\(<Time>\): pid=<PID> uid=<UID> auid=<AUID> ses=<SES> msg=\'<Content>\'",
#             "log_format": "type=<Type> msg=audit\(<Time>\): <Content>",
#             "regex": [r"\/(?:[\w-]+\/)+[\w-]+"],
#             "st":0.8,
#             "depth": 6,
#             "filter":1,
#             "iocs":1,
#         },
#         "auth": {
#             "log_format": "<Month> <Date> <Time> <Component> <Level>: <Content>",
#             "regex": [],
#             "st": 0.6,
#             "depth": 4,
#             "filter": 0,
#             "iocs":0,
#         },
#     "Process": {
#         "sysdig": {
#             "log_format": "<Time> <CPU_ID> <Command> \(<Threat_ID>\) <Event_Direction> <Type> <Arguments>",
#             "regex": [r"\/(?:[\w-]+\/)+[\w-]+", r"\b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b"],
#             "st": 0.7,
#             "depth": 4,
#             "filter": 0,
#             "iocs": 1,
#             },
#         },
#     }
# }


# the matching format for unstructured logs
# format_dict = {
#     "DNS": {
#         "dnsmasq": {
#             "log_format": "<Month> <Date> <Time> dnsmasq\[<PID>\]: <Content>",
#             # match the domain, ipv4 and ipv6
#             "regex": [r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", r"\b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"],
#             "st":0.7,
#             "depth":4,
#             # filter for domain name match with general domain extension
#             "filter": 1,
#             "iocs":0,
#         },
#     },
#     "Apache": {
#         "auth": {
#             "log_format": "<Month> <Date> <Time> <Component> <Level>: <Content>",
#             "regex": [],
#             "st": 0.6,
#             "depth": 4,
#             "filter": 0,
#             "iocs":0,
#         },

#     }
# }

