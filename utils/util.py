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

nlp = spacy.load("en_core_web_lg")

def struc_data_read():
    pass


def raw_data_read():
    pass

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