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

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)

class KVParser:

    def __init__(self, poi_list:list, log_filename:Path):
        self.PoI = poi_list
        self.format_output = {
            "Time":[],
            "Src_IP":[],
            "Dest_IP":[],
            "Proto":[],
            "Domain":[],
            "Parameters":[],
            "IOCs":[],
            "Actions":[],
            "Status":[],
            "Direction":[]
        }
        self.logs = Path(log_filename).read_text().splitlines()

    def split_pair(self, sen:str):
        ''' split key-value pair default by space with recursive setting --- 
        suitable for pure key-value pair matching
        
        '''
        key_value_pairs = []
        # check whether there is " or ' in sen
        if '"' in sen or "'" in sen:
            # the pattern can avoid splitting problem for " and '
            pattern = r'(?:[^"\s]+="[^"]*"|[^\'\s]+=\'[^\']*\'|[^"\s]+=[^\s]*)'
            key_value_pairs = re.findall(pattern, sen)
            for index, pair in enumerate(key_value_pairs):
                # check whether there is nested part
                if ':' in pair:
                    key, value = pair.split(":", 1)
                    key_value_pairs[index] = key
                    nested_pairs = self.split_pair(value)    
                    key_value_pairs.extend(nested_pairs)
        else:
            # implement general split
            key_value_pairs = sen.split(" ")

        return key_value_pairs


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
        return timestamp_datetime.strftime("%d-%m-%Y %H:%M:%S")

    def poi_ext(self, pairs: list):
        ''' extract poi from pairs split from one sentence
        
        '''
        ext_poi = {}
        # split pairs to key-value dict
        for pair in pairs:
            # remove timestamp part
            if pair.startswith("msg=audit"):
                ext_poi["timestamp"] = self.ext_format_time(pair)
                
            res = pair.split("=")
            key, value = res[0], res[1]
            if key in self.PoI:
                ext_poi[key] = value

        return ext_poi
    
    def log_parser(self):
        pass

    def get_output(self, log_type:str, app:str):
        ''' define the corresponding mapping from poi to column
        :param log_type: define the log type
        :param app: define the application name like apache
        '''
        # the mapping dict may be different from logs, consider application and log_type
        if app.lower() == "apache":
            if log_type.lower() == "audit":
                logger.info("generating the format output for {}-{} logs".format(app.lower(), log_type.lower()))
                '''
                    ["type", "timestamp", "acct", "exe", "res"]
                '''
                
                column_poi_map = {
                    "Time": ["timestamp"],
                    "Actions":["Type"],
                    "IOCs":["acct","exe"],
                    "Status":["res"],
                    "Direction":"->"
                }

                for log in self.logs:
                    # write data from extracted poi to format output

