"""
@Description : 
@Author      : Newt Tan (Wapiti08)
@Time        : 2023/11/24 14:51
@File        : util.py
"""

from zat.log_to_dataframe import LogToDataFrame
import spacy
import networkx as nx
import matplotlib.pyplot as plt
from tqdm import tqdm
import pandas as pd
from datetime import datetime
import re
import yaml

config = yaml.safe_load("./config.yaml")

nlp = spacy.load("en_core_web_lg")

def struc_data_read():
    pass


def raw_data_read():
    pass

def is_key_value_pair(element:str):
    # Define a regular expression pattern to match key-value pairs
    key_value_pattern = re.compile(r'^\w+=\S+$')
    # Check if the element matches the key-value pair pattern
    return bool(key_value_pattern.match(element))

def is_all_kv_pairs(args:list):
    for element in args:
        if not is_all_kv_pairs(element):
            return False
    
    return True

def time_format(log_df: pd.DataFrame):
    ''' convert any combination of <Month> <Day>/<Date> <Timestamp> <Year> 
    to single <Time> with unified format
    
    '''
    # check whether year exists in column, otherwise choose current year for default
    if "Year" not in log_df.columns:
        log_df["Year"] = len(log_df) * [datetime.now().year]
    if "Day" in log_df.columns:
        log_df["Time"] = pd.to_datetime(log_df[["Year", "Month", "Day", "Timestamp"]])
    elif "Date" in log_df.columns:
        log_df["Time"] = pd.to_datetime(log_df[["Year", "Month", "Date", "Timestamp"]])
    
    # format the time
    log_df['Time'] = log_df["Time"].dt.strftime("%d-%b-%Y %H:%M:%S")

    return log_df


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
            # create a named capture group
            regex += "(?P<%s>.*)" % header
            headers.append(header)
    regex = re.compile("^" + regex + "$")

    return headers, regex



