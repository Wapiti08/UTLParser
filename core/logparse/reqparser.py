'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-04 11:13:40
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-07 11:59:42
 # @ Description: The module to parse http request like logs
 '''

'''
    process log like access/http-request:
        10.35.33.116 - - [19/Jan/2022:07:50:57 +0000] "GET /wp-includes/css/dist/block-library/style.min.css?ver=5.8.3 HTTP/1.1" 200 10846 "http://intranet.price.fox.org/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"

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

class ReqParser:

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

    