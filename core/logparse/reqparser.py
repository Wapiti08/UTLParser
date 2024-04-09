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
import pandas as pd
from urllib.parse import urlparse
from core.pattern import domaininfo

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)


# define the default log format
log_format = "<SRC_IP> - - \[<Time>\] \"<Request_Method> <Content> <HTTP_Version>\" \
                <Status> <Response_Size> \"<Referer>\" \"<User_Agent>\"",

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
            "PID":[],
            "Actions":[],
            "Status":[],
            "Direction":[],
            "Label":[]

        }
        self.logs = Path(log_filename).read_text().splitlines()
    
    def domain_ext(self, referer_part):
        ''' 
        
        '''
        parsed_url = urlparse(referer_part)
        return parsed_url.netloc

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

    def poi_ext(self, regex, headers):
        ''' match the poi according to component regex
        
        general poi_list: src_ip, time, request_method, content (parameters),
            status, referer(domain), user_agent(tool name)
        '''
        log_messages = []

        for line in self.logs:
            try:
                # match every component
                match = regex.search(line.strip())
                message = [match.group(header) for header in headers]
                log_messages.append(message)
            except Exception as e:
                logger.warning("Skip line: %s", line)

        logdf = pd.DataFrame(log_messages, columns = headers)
        logdf.insert(0, 'LineId', None)
        logdf["LineId"] = logdf.index + 1
        # extract expected columns based on poi
        desired_columns = [header for header in headers if any(header.lower() == poi for poi in self.PoI)]
        print("Total lines: ", len(logdf))
        logdf = logdf[desired_columns]

        # extract the necessary part based on functions
        logdf['Time'] = logdf["Time"].apply(lambda x: self.time_parse(x))
        logdf["Content"] = logdf['Content'].apply(lambda x: self.url_para_ext(x))
        logdf['Referer'] = logdf['Referer'].apply(lambda x: self.domain_ext(x))
        logdf["User_Agent"] = logdf["User_Agent"].apply(lambda x: self.user_agent_ext(x))

        return logdf
    
    def get_output(self, label:int):
        '''
        
        '''
        start_time = datetime.now() 

        logger.info("generating the format output for {}-{} logs".format(self.app.lower(), self.log_type.lower()))
        column_poi_map = domaininfo.unstru_log_poi_map[self.app][self.log_type]

        if self.app.lower() == "apache":
            if "access" in self.log_type.lower():
                # generate the regex and headers
                headers, regex = self.gen_logformat_regex(log_format)
                logdf = self.poi_ext(regex, headers)
                log_num = len(logdf)

                for column, _ in self.format_output.items():
                    if column in ["Time", "Src_IP", "Status"]:
                        self.format_output[column] = logdf[column].tolist()
                    elif column in ["Domain", "Parameters","Actions","IOCs"]:
                        self.format_output[column] = logdf[column_poi_map[column]].tolist()
                    elif column == "Direction":
                        self.format_output[column] = [column_poi_map[column]] * log_num 
                    elif column == "Label":
                        self.format_output[column] = [label] * log_num
                    else:
                        self.format_output[column] = ["-"] * log_num

                logger.info("the parsing output is like: {}".format(self.format_output))


        pd.DataFrame(self.format_output).to_csv(
            Path(self.savePath).joinpath(self.logName + "_unifrom.csv"), index=False
        )

        logger.info("Unified Output is Done. [Time taken: {!s}]".format(datetime.now() - start_time))


    