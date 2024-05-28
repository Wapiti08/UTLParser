'''
 # @ Create Time: 2024-04-02 18:38:16
 # @ Modified time: 2024-04-02 18:38:21
 # @ Description: the module to generate ground truth dataset
 ''' 
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from core.logparse.genparser import GenLogParser
import config
import re
import pandas as pd

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
            "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
            # match the ip, port, id
            "regex": [config.regex['ip4'],config.regex['port'],config.regex['id']],
            "st": 0.2,
            "depth": 4,
        },
        "audit": {
            "log_format": "<Type> <Time>: <Content>",
            # match the ip, port, id
            "regex": [config.regex['ip4'],config.regex['port'],config.regex['id']],
            "st": 0.2,
            "depth": 6,
        },
    },
    "Linux": {
        "syslog":{
            "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
            # match path
            "regex": [config.regex['path_unix'],config.regex['domain'],config.regex['ip_with_port'],config.regex['ip4']],
            "st": 0.2,
            "depth":6,
        }
    },
}

# use genlogparser to generate initial structured csv and manually correct them
def genlog_output(datafile: str, app:str, log_type:str, outputfile:str):
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
            indir=datafile,
            outdir=outputfile,
            log_format=log_format,
            keep_para=True,
            maxChild=100,
            poi_list=[],
    )

    logparser.parse("{}.log".format(log_type))

def kv_template(content:list):
    # Initialize an empty list to store the extracted values
    template_list = []
    values_list = []
    # Iterate over each string in the list
    for string in content:
        if string != '':
            if "'" in string:
                string = string.replace("'",'')
                # have further split
                sub_pairs = string.split(" ")
                for pair in sub_pairs:
                    key, value = pair.rsplit('=', 1)
                    values_list.append(value)
                    value = '<*>'
                    template_list.append(f"{key}={value}")
            else:
                # Split the string into key and value parts
                key, value = string.rsplit('=', 1)  # Split only at the first '='
            
                values_list.append(value)
                # Replace the value with '<*>'
                value = '<*>'
                # Append the modified key-value pair to the template list
                template_list.append(f"{key}={value}")
            # Append the original value to the values list
                
    template = " ".join(template_list)
    return template, values_list

def kv_split(sen):
    key_value_pairs = []
    pattern = r'(?:[^"\s]+="[^"]*"|[^\'\s]+=\'[^\']*\'|[^"\s]+=[^\s]*)'
    # check whether there is " or ' in sen  ---- audit 
    if '"' in sen or "'" in sen:
        # the pattern can avoid splitting problem for " and '
        key_value_pairs = re.findall(pattern, sen)
        for index, pair in enumerate(key_value_pairs):
            # check whether there is nested part
            if '):' in pair:
                key, value = pair.rsplit(":", 1)
                key_value_pairs[index] = key
                nested_pairs = kv_split(value)    
                key_value_pairs.extend(nested_pairs)
    else:
        # implement general split
        key_value_pairs = sen.split(" ")

    return key_value_pairs

# use script to generate ground truth data for audit data
def kvlog_output(datafile: str, app:str, log_type:str, outputfile:str):
    # create csv with column names Type, Time, Content, EventTemplate, ParameterList
    log_format = format_dict[app][log_type]['log_format']

    column_dict = {
        "Type": [],
        "Time": [],
        "Content": [],
        "EventTemplate": [],
        "ParameterList": []
    }
    with open(datafile, 'r') as logfile:
        data = logfile.readlines()
        kv_pairs = []
        for sen in data:
            kv_pairs = kv_split(sen)
            for kv_pair in kv_pairs:
                if kv_pair.startswith("type"):
                    column_dict["Type"].append(kv_pair.split("=")[0])
                elif kv_pair.startswith("msg=audit"):
                    column_dict["Time"].append(kv_pair.split("(")[1].split(":")[0])

            column_dict["Content"].append(" ".join(kv_pairs[2:]))
            template, parameterlist = kv_template(kv_pairs[2:])
            column_dict["EventTemplate"].append(template)
            column_dict["ParameterList"].append(parameterlist)

        df = pd.DataFrame(column_dict, columns = list(column_dict.keys()))
        df.to_csv(outputfile)

if __name__ == "__main__":
    log_apps = ["Apache"]
    log_types = ["audit"]
    # log_apps = ["DNS", "Apache", "Linux"]
    # log_types = ["dnsmasq", "auth", "syslog"
    cur_path = Path.cwd()
    for app, type in zip(log_apps, log_types):
        input_data_path = cur_path.joinpath("data").as_posix()
        output_data_path = cur_path.joinpath("data", "result").as_posix()
        genlog_output(input_data_path, app, type, output_data_path)


    # sen = '''type=SERVICE_START msg=audit(1642207163.978:391): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=phpsessionclean comm="systemd" exe="/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'''
    # print(kv_split(sen))
    # input_data_path = cur_path.joinpath("data", "audit.log").as_posix()
    # output_data_path = cur_path.joinpath("data", "result", "audit.log_structured.csv").as_posix()
    # kvlog_output(input_data_path, 'Apache',"audit", output_data_path)