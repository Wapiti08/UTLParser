'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-04-02 18:38:16
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-04-02 18:38:21
 # @ Description: the module to generate ground truth dataset
 ''' 
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from core.logparse.genparser import GenLogParser
import config

# calculated result from uniform
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
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            # match the ip, port, id
            "regex": [config.regex['ip4'],config.regex['port'],config.regex['id']],
            "st": 0.2,
            "depth": 4,
        },
        "access": {
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            # match the ip, port, id
            "regex": [config.regex['ip4'],config.regex['port'],config.regex['id']],
            "st": 0.7,
            "depth": 4,
        },
    },
    "Linux": {
        "syslog":{
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            # match path
            "regex": [config.regex['path_unix'],config.regex['domain']],
            "st": 0.2,
            "depth":6,
        }
    },
}

# use genlogparser to generate initial structured csv and manually correct them
def genlog_output(datafile: str, app:str, log_type:str):
    '''
    
    '''
    rex = format_dict[app][log_type]['regex']
    log_format = format_dict[app][log_type]['log_format']
    depth = format_dict[app][log_type]['depth']
    st = format_dict[app][log_type]['st']

    logparser = GenLogParser(
        depth=depth,
            st=st,
            rex = rex,
            indir="./data/",
            outdir="../../data/result/",
            log_format=log_format,
            keep_para=True,
            maxChild=100,
            poi_list=[],
    )

    logparser.parse()
    


# use script to generate ground truth data for audit data
def kvlog_output():