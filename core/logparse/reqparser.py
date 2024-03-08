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


# define the default log format
log_format = "<SRC_IP> - - \[<Time>\] \"<Request_Method> <Content> <HTTP_Version>\" \
                <Status_Code> <Response_Size> \"<Referer>\" \"<User_Agent>\"",

class ReqParser:

    def __init__(self, log_filename:Path, poi_list:list):
        ''' 
        :param poi_list: src_ip, time, request_method, content (parameters),
                         status, referer(domain), user_agent(tool name)
        '''
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
    
    def url_para_ext(self, content_part):
        ''' extract the parameters from request content based on question mark
        
        '''
        # check whether ? exists in content
        if "?" in content_part:
            paras = content_part.split("?")[1]
        else:
            return "-"
    
    def gen_logformat_regex(self, logformat):
        '''
        
        '''
        headers = []
        # split the strings that start with '<', followed by one or more characters that
        # are not angle brackets and then end with ">"
        splitters = re.split(r"(<[^<>]+>)", logformat)
        regex = ""
        for k in range(len(splitters)):
            if k % 2 == 0:
                # process the space between adjacent components
                splitter = re.sub(" +", "\\\s+", splitters[k])
                regex += splitter
            else:
                header = splitters[k].strip("<").strip(">")
                # create a named capture group
                regex += "(?P<%s>.*)" % header
                headers.append(header)
        regex = re.compile("^" + regex + "$")

        return headers, regex

    
    def time_parse(self, time_string):
        ''' change the time format to unified format
        
        '''
        # define the input and output format --- %b is the abbreviated month name
        input_format = "%d/%b/%Y:%H:%M:%S %z"
        output_format = "%d-%m-%Y %H:%M:%S"

        # parse the input string using input format
        parsed_date = datetime.strftime(time_string, input_format)

        formatted_date = parsed_date.strftime(output_format)

        return formatted_date

    def user_agent_ext(self, user_agent_part):
        ''' optional: extract the user agent names
        
        '''
        browser_regex = r'([^\s/]+)(?=/\d+\.\d+)'
        browser_names = re.findall(browser_regex, user_agent_part)
        return browser_names

    def poi_ext(self,):
        '''
        
        '''


    
    def get_output(self,):
        '''
        
        '''

    

    