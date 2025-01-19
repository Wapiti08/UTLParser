'''
 # @ Create Time: 2024-03-04 11:13:40
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
import cfg
import ray
import multiprocessing

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)


# define the default log format
log_format = "<Src_IP> - - \[<Time>\] \"<Request_Method> <Content> <HTTP_Version>\" \
                <Status> <Response_Size> \"<Referer>\" \"<User_Agent>\"",

@ray.remote
def parse_log_chunk(chunk, regex, headers, poi_list, time_parser, \
                    url_parser, domain_extractor, user_agent_extractor):
    log_messages = []
    for line in chunk:
        try:
            # match every component
            match = regex.search(line.strip())
            message = [match.group(header) for header in headers]
            log_messages.append(message)
        except Exception as e:
            logger.warning("Skip line: %s", line)
    
    logdf = pd.DataFrame(log_messages, columns = headers)
    if logdf.empty:
        return pd.DataFrame()
    
    # apply diverse lambda functions
    logdf["Time"] = logdf['Time'].apply(time_parser)
    logdf['Content'] = logdf["Content"].apply(url_parser)
    logdf["Referer"] = logdf["Referer"].apply(domain_extractor)
    logdf["User_Agent"] = logdf["User_Agent"].apply(user_agent_extractor)

    desired_columns = [header for header in headers if any(header.lower() == poi.lower() for poi in poi_list)]
    return logdf[desired_columns]


class ReqParser:

    def __init__(self, indir:str, outdir:dir, log_name:str, log_type:str, app:str):
        ''' 
        :param poi_list: src_ip, time, request_method, content (parameters),
                         status, referer(domain), user_agent(tool name)
        '''
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

        self.logs = Path(self.path).joinpath(self.logName).read_text().splitlines()
    
    @staticmethod
    def domain_ext(referer_part):
        ''' 
        
        '''
        parsed_url = urlparse(referer_part)
        return parsed_url.netloc

    @staticmethod
    def url_para_ext(content_part):
        ''' extract the parameters from request content based on question mark
        
        '''
        # check whether ? exists in content
        return content_part.split("?")[1] if "?" in content_part else "-"

    @staticmethod
    def gen_logformat_regex(logformat):
        '''
        
        '''
        headers = []
        # split the strings that start with '<', followed by one or more characters that
        # are not angle brackets and then end with ">"
        splitters = re.split(r"(<[^<>]+>)", logformat[0])
        regex = ""
        for k in range(len(splitters)):
            if k % 2 == 0:
                # process the space between adjacent components
                splitter = re.sub(" +", "\\\s+", splitters[k])
                regex += splitter
            else:
                header = splitters[k].strip("<").strip(">")
                # create a named capture group
                regex += "(?P<%s>.*?)" % header
                headers.append(header)
        return headers, re.compile("^" + regex + "$")

    @staticmethod
    def time_parse(time_string):
        ''' change the time format to unified format
        
        '''
        # define the input and output format --- %b is the abbreviated month name
        input_format = "%d/%b/%Y:%H:%M:%S %z"
        output_format = "%Y-%b-%d %H:%M:%S.%f"
        # parse the input string using input format
        parsed_date = datetime.strptime(time_string, input_format)

        return parsed_date.strftime(output_format)

    @staticmethod
    def user_agent_ext(user_agent_part):
        ''' optional: extract the user agent names
        
        '''
        browser_regex = r'([^\s/]+)(?=/\d+\.\d+)'
        browser_names = re.findall(browser_regex, user_agent_part)
        common_browsers = ["Mozilla", "AppleWebKit", "Chrome", "Safari", "Gecko", "Firefox"]

        return [ browser for browser in browser_names if browser not in common_browsers]

    def get_output(self, label:int):
        ''' 
        
        '''
        start_time = datetime.now() 

        logger.info("generating the format output for {}-{} logs".format(self.app.lower(), self.log_type.lower()))
        column_poi_map = domaininfo.unstru_log_poi_map[self.app][self.log_type]

        if self.app.lower() == "apache" and "access" in self.log_type.lower():
            # generate the regex and headers
            headers, regex = self.gen_logformat_regex(log_format)
            # generate chunks based on cpu number
            num_cpus = multiprocessing.cpu_count()
            chunk_size = len(self.logs) // num_cpus
            chunks = [self.logs[i:i + chunk_size] for i in range(0, len(self.logs), chunk_size)]
            parse_start_time = datetime.now() 
            # initialize ray and apply ray remote
            ray.init(runtime_env={"working_dir": Path.cwd().parent.as_posix()})
            results = ray.get([
                parse_log_chunk.remote(
                    chunk, regex, headers, self.PoI, self.time_parse, self.url_para_ext, self.domain_ext, self.user_agent_ext
                ) for chunk in chunks
            ])

            ray.shutdown()
            logdf = pd.concat(results, ignore_index=True)
            logger.info("Parsing Done. [Time taken: {!s}]".format(datetime.now() - parse_start_time))

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

                # logger.info("the parsing output is like: {}".format(self.format_output))

        pd.DataFrame(self.format_output).to_csv(
            Path(self.savePath).joinpath(self.logName + "_uniform.csv"), index=False
        )
        # pd.DataFrame(self.format_output).to_parquet(
        #     Path(self.savePath).joinpath(self.logName + "_uniform.parquet"), index=False
        # )

        logger.info("Unified Output is Done. [Time taken: {!s}]".format(datetime.now() - start_time))


    