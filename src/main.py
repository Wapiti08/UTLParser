import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
from utils import util
from core.logparse import kvparser
from core.logparse import reqparser
from core.logparse import genparser

def log_type_check(log_name:str):
    ''' check the processing logic according to the log type
    
    audit: key-value
    access: http request (network traffic)
    auth/windows/linux: general log type
    '''
    pass

def parse_log(log_type:str):
    pass


if __name__ == "__main__":
    log_type_check()
    parse_log()