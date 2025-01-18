"""
@Description : 
@Time        : 2023/11/24 14:51
@File        : util.py
"""
import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
from zat.log_to_dataframe import LogToDataFrame
import spacy
import networkx as nx
import matplotlib.pyplot as plt
from tqdm import tqdm
import pandas as pd
from datetime import datetime
import re
import cfg


nlp = spacy.load("en_core_web_lg")

def is_key_value_pair(element:str):
    ''' check whether a split token is key-value pair
    
    '''
    # Define a regular expression pattern to match key-value pairs
    key_value_pattern = re.compile(r'^\w+=\S+$')
    # Check if the element matches the key-value pair pattern
    return bool(key_value_pattern.match(element))

def is_all_kv_pairs(args:list):
    ''' check whether all the tokens are key value pairs
    
    '''
    for element in args:
        if not is_key_value_pair(element):
            return False
    
    return True


def time_format(log_df: pd.DataFrame):
    ''' convert any combination of <Month> <Day>/<Date> <Timestamp> <Year> 
    to single <Time> with unified format
    
    '''
    # check whether right format Time exists
    if "Time" in log_df.columns:
        try:
            log_df['Time'] = pd.to_datetime(log_df["Time"],errors='coerce')
            log_df["Time"] = log_df["Time"].dt.strftime("%Y-%b-%d %H:%M:%S.%f")
            return log_df
        except:
            if "Day" in log_df.columns:
                log_df["Time"] = pd.to_datetime(log_df[["Year", "Month", "Day", "Timestamp"]].astype(str).apply(' '.join, axis=1))
            elif "Date" in log_df.columns:
                log_df["Time"] = pd.to_datetime(log_df[["Year", "Month", "Date", "Timestamp"]].astype(str).apply(' '.join, axis=1))
            else:
                log_df["Day"] = len(log_df) * [datetime.now().day]
                log_df["Time"] = pd.to_datetime(log_df[["Year", "Month", "Day", "Time"]].astype(str).apply(' '.join, axis=1))

    # check whether year exists in column, otherwise choose current year for default
    if "Year" not in log_df.columns:
        log_df["Year"] = len(log_df) * [datetime.now().year]
    if "Month" not in log_df.columns:
        log_df["Month"] = len(log_df) * [datetime.now().strftime("%b")]
    if "timestamp" in log_df.columns:
        log_df['Timestamp'] = log_df['timestamp']
    if "Day" in log_df.columns:
        log_df["Time"] = pd.to_datetime(log_df[["Year", "Month", "Day", "Timestamp"]].astype(str).apply(' '.join, axis=1))
    elif "Date" in log_df.columns:
        log_df["Time"] = pd.to_datetime(log_df[["Year", "Month", "Date", "Timestamp"]].astype(str).apply(' '.join, axis=1))
    else:
        log_df["Day"] = len(log_df) * [datetime.now().day]
        log_df["Time"] = pd.to_datetime(log_df[["Year", "Month", "Day", "Timestamp"]].astype(str).apply(' '.join, axis=1))
    
    
            
    # format the time
    log_df['Time'] = log_df["Time"].dt.strftime("%Y-%b-%d %H:%M:%S.%f")

    return log_df

def token_filter(token:str):
    if "[" in token:
        extra_part_rex = r'\[.*?\] '
        # avoid query mistakenly recognized as NN tag
        return re.sub(extra_part_rex, 'ing ', token)
    else:
        return token

def gen_regex_from_logformat(logformat):
    ''' based on given logformat to generate the regex that matches the corresponding components
    :param logformat: given format components ---- based on specific log format
    one example would be: "<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>",

    '''
    headers = []
    # match any context inside <> without < and > themselves
    splitters = re.split(r"(<[^<>]+>)", logformat)

    regex = ""
    for k in range(len(splitters)):
        if k % 2 == 0:
            # process the space between adjacent components
            splitter = re.sub(" +", "\\\s+", splitters[k])
            regex += splitter
                
        else:
            header = splitters[k].strip("<").strip(">")
            # create a named capture group --- match only once or zero to avoid conflicts
            regex += "(?P<%s>.*?)" % header
            headers.append(header)
                
    regex = re.compile("^" + regex + "$")

    return headers, regex


def ip_match(test_string:str):
    ''' match all
    
    '''
    match_list = []
    # check ip with port first
    ip_port = cfg.regex["ip_with_port"]
    ipv4 = cfg.regex["ip4"]
    ipv6 = cfg.regex["ip6"]

    for ip_regex in [ip_port, ipv4, ipv6]:
        res = re.search(ip_regex, test_string)
        if res:
            for ip in re.findall(ip_regex, test_string): 
                match_list.append(ip)
            return match_list
        else:
            continue


def port_match(test_string:str):
    ''' match all
    
    '''
    match_list = []
    # check port
    port_regex = cfg.regex["port"]

    res = re.search(port_regex, test_string)
    if res:
        for port in re.findall(port_regex, test_string): 
            match_list.append(port)
        return match_list
    else:
        return None

def split_commands_check(string_list: list):
    ''' check split commands and join them if they are
    
    '''
    command = ''
    new_string_list = []
    for index, string in enumerate(string_list):
        if '/bin' in string:
            command = ' '.join(string_list[index:])
            new_string_list.append(command)
            break
    
    if len(new_string_list) > 0:
        string_list[index:] = [command]
        return string_list
    else:
        return string_list


def path_match(test_string:str):
    ''' signal match check
    
    '''
    match_list = []
    path_win = cfg.regex["path_win"]
    path_unix = cfg.regex["path_unix"]
    for path_regex in [path_win, path_unix]:
        res = re.search(path_regex, test_string)
        if res:
            for path in re.findall(path_regex, test_string):
                # remove sub matching
                match_list.append(path[0])
            return match_list
        else:
            continue

def domain_match(test_string:str):
    ''' signal match check
    
    '''
    match_list = []
    domain_rex = cfg.regex["domain"]
    res = re.search(domain_rex, test_string)
    if res:
        for domain in re.findall(domain_rex, test_string):
            match_list.append(domain)
        return match_list
    else:
        return None
