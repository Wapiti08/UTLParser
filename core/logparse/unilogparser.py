import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
from utils import util
from core.logparse import kvparser
from core.logparse import reqparser
from core.logparse import genparser
import yaml

with open("./config.yaml", 'r') as configfile:
    config = yaml.safe_load(configfile)

class LogParser:
    def __init__(self, log_name, ioc_list):
        self.log_name = self.log_type_check(log_name)

    def log_type_check(self):
        ''' extract the name part
        
        '''
        pass

    def choose_logparser(self,):
        if self.log_name in config["log_type"]["kv"]:
            kvparser.KVParser(log_filename=self.log_name)
        elif self.log_name in config["log_type"]["req"]:
            reqparser.ReqParser()
        elif self.log_name in config["log_type"]["gen"]:
            genparser.GenLogParser()
