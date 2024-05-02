'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-05-01 09:19:48
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-05-01 09:20:28
 # @ Description: measure the transformation efficiency through iocs coverage and labelling accuracy
 '''

from core.logparse.kvparser import KVParser
from core.logparse.genparser import GenLogParser
from core.logparse.reqparser import ReqParser
from core.logparse.strreader import StrLogParser
from pathlib import Path
import pandas as pd
import json
import config

format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Month> <Date> <Timestamp> <Component>: <Content>",
            # match the domain, ipv4 and ipv6
            "regex": [config.regex['domain'], config.regex['ip4'], config.regex['ip6']],
            "st":0.3,
            # right
            'depth':4,
        },
    },
    "Apache": {
        "auth": {
            "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
            # match the ip, port, id
            "regex": [config.regex['ip4'],config.regex['port'],config.regex['id']],
            "st": 0.33,
            "depth": 4,
        },
    }
    }

def value_match(ioc_list:list, data: list):
    iocs_num = 0
    for log_string in data:
        if any(threat in log_string for threat in ioc_list):
            iocs_num += 1
    return iocs_num


def value_set_match(iocs_list:list, data: list):
    ano_log_num = 0
    for log_string in data:
        for iocs in iocs_list:
            if all( ioc in log_string for ioc in iocs):
                ano_log_num += 1
    return ano_log_num


def iocs_coverage(labelled_data, ioc_indicitors:list, check_position:dict, 
                  data_type:str):
    ''' calculate iocs coverage for specific log type

    :param labelled_data: the original malicious logs
    :param ioc_indicitors: the list of ioc element
    :param check_position: the place to match iocs according to types {iocs: {ip: [], domain:[]}}
    :param data_type: log type
    '''

    cur_path = Path.cwd()
    indir = cur_path.joinpath("data").as_posix()
    outdir = cur_path.joinpath("data","result").as_posix()

    iocs_num = 0
    # extract all iocs according to ioc_indicitors
    iocs_num = value_match(ioc_indicitors, labelled_data)

    # parse labelled logs into uniformed csv
    if data_type == "conn":
        logparser = StrLogParser(
            indir = indir,
            outdir= outdir,
            log_name="conn.log",
            log_type=data_type,
            app = "zeek"
        )
    
    elif data_type == "audit":
        logparser = KVParser(
            indir=indir,
            outdir=outdir,
            log_name='audit.log',
            log_type='audit',
            app='apache',
        )
    
    elif data_type == "access":
        logparser = ReqParser(
            indir=indir,
            outdir=outdir,
            log_name='access.log',
            log_type='access',
            app='apache',)

    else:
        if data_type == "auth":
            rex = format_dict["Apache"][data_type]['regex']
            log_format = format_dict['Apache'][data_type]['log_format']
            depth = format_dict['Apache'][data_type]['depth']
            st = format_dict['Apache'][data_type]['st']

        elif data_type == "dnsmasq":
            rex = format_dict["DNS"][data_type]['regex']
            log_format = format_dict['DNS'][data_type]['log_format']
            depth = format_dict['DNS'][data_type]['depth']
            st = format_dict['DNS'][data_type]['st']

        logparser = GenLogParser(
            depth=depth,
            st=st,
            rex = rex,
            indir=indir,
            outdir=outdir,
            log_format=log_format,
            log_name="{}.log".foramt(data_type),
            keep_para=True,
            maxChild=100,
        )

    logparser.log_parse()

    # match all the iocs and calculate the coverage
    try:
        uni_df = pd.read_parquet(Path(outdir).joinpath(data_type + "_uniform.parquest"))
    except:
        uni_df = pd.read_csv(Path(outdir).joinpath(data_type + "_uniform.csv"))

    matched_iocs_num = 0
    for column, ioc_dict in check_position.items():
        for ioc_type, ioc_list in ioc_dict.items():
            matched_iocs_num += value_match(ioc_list, uni_df[column].tolist())

    iocs_coverage = round(matched_iocs_num/iocs_num,4)  
    print("iocs coverage for {} is: ".format(data_type, iocs_coverage))

    return iocs_coverage


def label_acc(ano_uniform_df, iocs_set_indicitors:list, match_position: list, 
              data_type:str):
    ''' calculate labelling accuracy for specific log type
    
    :param uniform_df: the unified output
    :param iocs_set_indicitors: the iocs list with embedded iocs set
    :param match_position: the place to match set of iocs, name of iocs locations
    :param data_type: log type
    '''
    match_series = ano_uniform_df[match_position].apply(lambda row: ' '.join(row.values.astype(str)), axis=1).tolist()
    matched_label_num = 0
    matched_label_num = value_set_match(iocs_set_indicitors, match_series)
    
    lab_acc = round(matched_label_num/len(ano_uniform_df),4)
    print("iocs coverage for {} is: ".format(data_type, lab_acc))

    return lab_acc
    
def label_csv_data(uniform_csv_path, label_data_path):
    ''' based on index information in label_data to mark anomaly in uniform_df
    
    :param uniform_df: csv framework with lineId
    '''
    try:
        uni_df = pd.read_parquet(Path(outdir).joinpath(data_type + "_uniform.parquest"))
    except:
        uni_df = pd.read_csv(Path(outdir).joinpath(data_type + "_uniform.csv"))

    with label_data_path.open("r") as fr:
        data = fr.readlines()
    malicious_lines = []
    
    for line in data:
        log = json.loads(line)
        malicious_lines.append(log["line"])
    
    return uni_df.iloc[malicious_lines]
    
def labelled_data_ext(data_path, label_data_rule):
    with data_path.open("r") as fr:
        data = fr.readlines()

    malicious_lines = []
    
    for line in data:
        log = json.loads(line)
        # minus one to get index
        malicious_lines.append(data[log["line"]-1])
    
    return malicious_lines

if __name__ == "__main__":

    data_type_list = ["access", "audit", "auth", "conn", "dnsmasq", "error"]
    
    cur_path = Path.cwd()
    indir = cur_path.joinpath("data").as_posix()
    outdir = cur_path.joinpath("data","result").as_posix()

    for data_type in data_type_list:
        # load 



    