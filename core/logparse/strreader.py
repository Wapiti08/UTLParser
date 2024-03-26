'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-06 09:29:18
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-06 11:12:59
 # @ Description: Structured Log Parsing Module
'''


'''
    read data from structured data like zeek logs
'''

from zat.log_to_dataframe import LogToDataFrame
import yaml
import logging
from pathlib import Path
from datetime import datetime
from core.pattern import domaininfo
import pandas as pd

config = yaml.safe_load("./config.yaml")

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)

class StrLogParser:

    def __init__(self, log_filename:Path, poi_list:list, log_type:str, app:str):
        
        self.PoI = poi_list
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
            "Direction":[]
        }
        self.log_type = log_type
        self.app = app
        
        # read structured logs    
        log_to_df = LogToDataFrame()
        # keep the ts column
        self.df = log_to_df.create_dataframe(self.input_file,ts_index=False)
    

    def format_ts(self, timestamp: float):
        datetime_obj = datetime.fromtimestamp(timestamp)
        return datetime_obj.strftime("%d-%b-%Y %H:%M:%S")

    def log_parse(self, log_name:str ):
        ''' extract necessary columns according to poi list, save computation resource
        
        '''
        return self.df[self.PoI].to_dict()

    def get_output(self, log_type:str, app;str):

        logger.info("generating the format output for {}-{} logs".format(app.lower(), log_type.lower()))
        column_poi_map = domaininfo.stru_log_poi_map[self.app][self.log_type]
        sum_poi_dict = self.log_parse(log_type)
        log_num = len(self.df)
        for column, _ in self.format_output.items():
            if column in column_poi_map.keys():
                self.format_output[column] = sum_poi_dict[column_poi_map[column]]
            else:
                self.format_output[column] = ["-"] * log_num

        logger.info("the parsing output is like: {}".format(self.format_output))

        pd.DataFrame(self.format_output).to_csv(
            Path(self.savePath).joinpath(self.logName + "_unifrom.csv"), index=False
        )


