'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-04 11:14:01
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-06 11:11:53
 # @ Description: Key_Value Pair Log Parsing Module
'''

'''
    process logs like audit:
        type=CRED_DISP msg=audit(1642267021.539:851): pid=15420 uid=0 auid=0 ses=123 msg='op=PAM:setcred acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
    PoI: type, timestamp, acct, exe, res
'''
import re
from datetime import datetime
import logging
from tqdm import tqdm
from pathlib import Path
import yaml
from utils import util
from core.pattern import domaininfo
import pandas as pd
import config

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)


class KVParser:

    def __init__(self, indir:str, outdir:str, log_name:str, \
                 log_type:str, app:str):
        '''
        :param poi_list: for example: ["type", "timestamp", "acct", "exe", "res"]
        '''
        self.PoI = config.POI[app][log_type]
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
        self.logName = log_name
        self.path = indir
        self.savePath = outdir
        self.log_type = log_type
        self.app = app

        self.logs = Path(self.path).joinpath(self.logName).read_text().splitlines()


    def split_pair(self, sen:str):
        ''' for audit logs,
        split key-value pair default by space with recursive setting --- 
        suitable for pure key-value pair matching
        
        '''
        key_value_pairs = []
        pattern = r'(?:[^"\s]+="[^"]*"|[^\'\s]+=\'[^\']*\'|[^"\s]+=[^\s]*)'
        if self.log_type == "audit":
            # check whether there is " or ' in sen  ---- audit 
            if "'" in sen or '"' in sen:
                sen = sen.replace("'","")
                sen = sen.replace('"','')
                # the pattern can avoid splitting problem for " and '
                key_value_pairs = re.findall(pattern, sen)
                for index, pair in enumerate(key_value_pairs):
                    # check whether there is nested part
                    if '):' in pair:
                        # split the last :
                        key, value = pair.rsplit(":", 1)
                        key_value_pairs[index] = key
                        nested_pairs = self.split_pair(value)    
                        key_value_pairs.extend(nested_pairs)
            else:
                # implement general split
                key_value_pairs = sen.split(" ")

        elif self.log_type == "process":
            if self.app == "sysdig":
                # read specific format
                proces_format = config.format[self.log_type][self.app]
                # create key value pair for previous part
                headers, regex = util.gen_regex_from_logformat(proces_format)
                res = self.header_value_pair(sen, regex, headers)
                if res:
                    # remove the last content to have second-level split
                    key_value_pairs.extend(res)

        return key_value_pairs

    def args_parse(self, args:str ):
        ''' for process log, 
        further process special args with poi: fd, path and potential sub event
        
        '''
        def blank_value(poi_list, poi_dict):
            for poi in poi_list:
                poi_dict[poi] = '-'
            return poi_dict
        
        args_dict = {}
        # check whether args contains other structure
        args_tokens = args.split("=",1)
        if len(args_tokens[1].split(" ")) == 1:
            # define the first element default as event_type
            args_dict["event_type"] = args_tokens[1]
            args_dict["sub_event"] = '-'
            args_dict["src_ip"] = '-'
            args_dict["dest_ip"] = '-'
            args_dict['path'] = '-'
            return args_dict
        else:
            args_sub_tokens = args_tokens[1].split(' ')
            args_dict["event_type"] = args_sub_tokens[0]
            if not util.is_all_kv_pairs(args_sub_tokens):
                # match the sub event by matching the ">"
                if ">" in args_sub_tokens:
                    args_dict["sub_event"] = args_sub_tokens[args_sub_tokens.index(">") + 1] 
                else:
                    args_dict["sub_event"] = '-'

            # process other kv pairs
            for pair in args_sub_tokens[1:]:
                if "=" in pair:
                    # split key-value pair
                    res = pair.split("=")
                    key, value = res[0], res[1]
                    # further process to extract precise values
                    res = self.value_check(value)
                    if key in self.PoI:
                        # check the type
                        if isinstance(res, list):
                            if len(res) == 2:
                                args_dict["src_ip"] = res[0]
                                args_dict["dest_ip"] = res[1]
                                args_dict = blank_value(['path'], args_dict)
                            elif len(res) == 1:
                                args_dict["path"] = res[0]
                                args_dict = blank_value(['src_ip', 'dest_ip'], args_dict)
                            else:
                                args_dict = blank_value(['path', 'src_ip', 'dest_ip'], args_dict)

                        else:
                            args_dict = blank_value(['path', 'src_ip', 'dest_ip'], args_dict)

                    else:
                        args_dict = blank_value(['path', 'src_ip', 'dest_ip'], args_dict)

                else:
                    args_dict = blank_value(['path', 'src_ip', 'dest_ip'], args_dict)

            return args_dict

    def value_check(self, value_string: str):
        ''' extract only value like path/domain/ip/username by giving the keyname
        
        '''

        # for process related value check
        proc_val_pattern = r'^(\d+)\(([^()]+)\)$'
        res = re.match(proc_val_pattern, value_string)
        # match ip or ip with port
        if res:
            content = res.group(2)
            # check whether ip or path
            if "->" in content:
                # match the src and/or dest ip with port
                return util.ip_match(content)
            else:
                return util.ip_match(value_string)

        # match the path 
        if "\\" in value_string or "/" in value_string:
            return util.path_match(value_string)
        
        # match the domain
        if "." in value_string:
            return util.domain_match(value_string)
        
        # filename
        return value_string


    def header_value_pair(self, sen, regex, headers):
        ''' generate the key value pair according to headers and regex matching
        
        '''
        kv_pairs = []
        try:
            match = regex.search(sen.strip())
            message = [match.group(header) for header in headers]
            message = [mes for mes in message if mes != '' ]
            # generate pairs
            for header, message in zip(headers, message):
                kv_pairs.append(f"{header.lower()}={message}")

        except Exception as e:
            logger.warning("Skip line: %s", sen)
            return None
        
        return kv_pairs

    def ext_format_time(self, time_pair: str):
        ''' extract seconds to format time, the example is like:
        msg=audit(1642516741.631:2492)
        
        '''
        # Extracting the timestamp part
        timestamp_str = time_pair.split("(")[1].split(":")[0]
        # Converting timestamp string to a float
        timestamp_float = float(timestamp_str)
        # Converting the timestamp to a datetime object
        timestamp_datetime = datetime.fromtimestamp(timestamp_float)
        # Formatting datetime object to the desired format
        return timestamp_datetime.strftime("%Y-%b-%d %H:%M:%S.%f")

    def poi_ext(self, pairs: list):
        ''' extract poi from pairs split from one sentence
        
        '''
        ext_poi = {}
        # split pairs to key-value dict
        for pair in pairs:
            if pair != '':
                # remove timestamp part
                if pair.startswith("msg=audit"):
                    ext_poi["timestamp"] = self.ext_format_time(pair)
                
                res = pair.split("=")
                key, value = res[0], res[1]
                if key in self.PoI:
                    if value != "?":
                        ext_poi[key] = value
        return ext_poi
    
    def log_parse(self, ):
        ''' process logs into a list of ioc mapping dict
        
        '''
        # define the sum poi dict to save the extracted poi from per log
        sum_poi_dict = {}
        for poi in self.PoI:
            sum_poi_dict[poi] = []

        for log in tqdm(self.logs, desc="parsing {} logs...".format(self.log_type)):
            kv_pairs = self.split_pair(log)
            if kv_pairs:
                if self.log_type == "audit":
                    poi_dict = self.poi_ext(kv_pairs)
                elif self.log_type == "process":
                    # check whether there is args part
                    poi_dict = self.poi_ext(kv_pairs[:-1])
                    poi_dict.update(self.args_parse(kv_pairs[-1]))

                # check missing poi value
                for poi in self.PoI:
                    if poi not in poi_dict.keys():
                        sum_poi_dict[poi].append('-')
                    else:
                        sum_poi_dict[poi].append(poi_dict[poi])

        return sum_poi_dict

    def get_output(self, label: int):
        ''' define the corresponding mapping from poi to column
        :param log_type: define the log type
        :param app: define the application name like apache
        '''
        start_time = datetime.now() 

        logger.info("generating the format output for {}-{} logs".format(self.app.lower(), self.log_type.lower()))
        # the mapping dict may be different from logs, consider application and log_type
        column_poi_map = domaininfo.unstru_log_poi_map[self.app][self.log_type]

        if self.app.lower() == "apache":
            if self.log_type.lower() == "audit":
                sum_poi_dict = self.log_parse()
                if sum_poi_dict != {}:
                    # write data from extracted poi to format output
                    ## get the length of logs
                    log_num = len(self.logs)
                    for column, _ in self.format_output.items():
                        if column == "IOCs":
                            tuple_0_list = sum_poi_dict[column_poi_map[column][0]]
                            tuple_1_list = sum_poi_dict[column_poi_map[column][1]]
                            self.format_output[column] = list(zip(tuple_0_list, tuple_1_list))
                        elif column == "Direction":
                            self.format_output[column] = [column_poi_map[column]] * log_num 
                        elif column == "Label":
                            self.format_output[column] = [label] * log_num
                        # exist poi for this column
                        elif column in column_poi_map.keys():
                            self.format_output[column] = sum_poi_dict[column_poi_map[column]]
                        else:
                            self.format_output[column] = ["-"] * log_num
                else:
                    logger.warn("Parsing error for {} log".format(self.log_type))
                    return
                
                # logger.info("the parsing output is like: {}".format(self.format_output))

        elif self.app.lower() == "sysdig":
            if self.log_type.lower() == "process":
                sum_poi_dict = self.log_parse()
                if sum_poi_dict != {}:
                    # grab both potential ip direction information and process call information
                    # process is the src node, pid 
                    log_num = len(self.logs)
                    for column, _ in self.format_output.items():
                        if column in ["Time", "Actions", "Proto", "PID"]:
                            self.format_output[column] = sum_poi_dict[column_poi_map[column]]
                        elif column == "Parameters":
                            if column_poi_map[column] in sum_poi_dict.keys():
                                self.format_output[column] = sum_poi_dict[column_poi_map[column]]
                            else:
                                self.format_output[column] = ['-'] * log_num
                        elif column in ["Src_IP", "Dest_IP"]:
                            # check whether there is corresponding value in fd or hostname
                            if column.lower() in sum_poi_dict.keys():
                                self.format_output[column] = sum_poi_dict[column.lower()]
                            else:
                                self.format_output[column] = ['-'] * log_num
                        elif column == "Label":
                            self.format_output[column] = [label] * log_num
                        elif column == "IOCS":
                            for index, key_name in enumerate(column_poi_map[column]):
                                if key_name in sum_poi_dict.keys():
                                    self.format_output[column][index] = sum_poi_dict[key_name]
                        elif column == "Direction":
                            self.format_output[column] = [column_poi_map[column]] * log_num 
                        else:
                            self.format_output[column] = ['-'] * log_num 
                
                else:
                    logger.warn("Parsing error for {} log".format(self.log_type))
                    return
        
        log_df = pd.DataFrame(self.format_output) 
        # format time
        log_df = util.time_format(log_df)
        
        log_df[list(self.format_output.keys())].to_csv(
            Path(self.savePath).joinpath(self.logName + "_uniform.csv"), index=False
        )
        # log_df[list(self.format_output.keys())].to_parquet(
        #     Path(self.savePath).joinpath(self.logName + "_uniform.parquet"), index=False
        # )
        logger.info("Unified Output is Done. [Time taken: {!s}]".format(datetime.now() - start_time))
