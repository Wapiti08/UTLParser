'''
 # @ Create Time: 2024-03-06 09:29:18
 # @ Modified time: 2024-03-06 11:12:59
 # @ Description: Structured Log Parsing Module
'''


'''
    read data from structured data like zeek logs
'''

from zat.log_to_dataframe import LogToDataFrame
import logging
from pathlib import Path
from datetime import datetime
from core.pattern import domaininfo
import pandas as pd
import cfg
import pandas as pd

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)

class StrLogParser:

    def __init__(self, indir:str, outdir:dir, log_name:str, log_type:str, app:str):
        
        self.PoI = cfg.POI[app][log_type]
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
        
        # read structured logs    
        log_to_df = LogToDataFrame()
        # keep the ts column
        self.df = log_to_df.create_dataframe(Path(self.path).joinpath(log_name),ts_index=False)
    

    def format_ts(self, timestamp: float):
        datetime_obj = datetime.fromtimestamp(timestamp)
        return datetime_obj.strftime("%Y-%b-%d %H:%M:%S.%f")

    def log_parse(self,):
        ''' extract necessary columns according to poi list, save computation resource
        
        '''
        return self.df[self.PoI]

    def get_output(self,):

        logger.info("generating the format output for {}-{} logs".format(self.app.lower(), \
                                                                         self.log_type.lower()))
        column_poi_map = domaininfo.stru_log_poi_map[self.app][self.log_type]
        sum_poi_dict = self.log_parse()
        log_num = len(self.df)
        for column, _ in self.format_output.items():
            if column in column_poi_map.keys():
                if isinstance(column_poi_map[column], list):
                    self.format_output[column] = \
                        sum_poi_dict.apply(lambda row: [row[col] for col in column_poi_map[column]], axis=1)
                else:
                    if column == "Direction":
                        self.format_output[column] = [column_poi_map[column]] * log_num
                    else:
                        self.format_output[column] = sum_poi_dict[column_poi_map[column]]
            else:
                self.format_output[column] = ["-"] * log_num

        # logger.info("the parsing output is like: {}".format(self.format_output))
        for key, value in self.format_output.items():
            print(len(value))
        # pd.DataFrame(self.format_output).to_csv(
        #     Path(self.savePath).joinpath(self.logName + "_uniform.csv"), index=False
        # )
        pd.DataFrame(self.format_output).to_parquet(
            Path(self.savePath).joinpath(self.logName + "_uniform.parquest"), index=False
        )



