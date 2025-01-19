'''
 # @ Create Time: 2024-05-01 09:19:48
 # @ Modified time: 2024-05-01 09:20:28
 # @ Description: measure the transformation efficiency through iocs coverage and labelling accuracy
 '''
import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
from core.logparse.kvparser import KVParser
from core.logparse.genparser import GenLogParser
from core.logparse.reqparser import ReqParser
from core.logparse.strreader import StrLogParser
import pandas as pd
import json
import cfg

format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Month> <Date> <Timestamp> <Component>: <Content>",
            # match the domain, ipv4 and ipv6
            "regex": [cfg.regex['domain'], cfg.regex['ip4'], cfg.regex['ip6']],
            "st":0.3,
            'depth':4,
        },
    },
    "Apache": {
        "auth": {
            "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
            # match the ip, port, id
            "regex": [cfg.regex['ip4'],cfg.regex['port'],cfg.regex['id']],
            "st": 0.33,
            "depth": 4,
        },
        "error": {
            "log_format": "\[<Week> <Month> <Day> <Timestamp> <Year>\] \[<Proto>\] \[pid <PID>\] \[client <Src_IP>\] <Content>",
            # match the path, port, id
            "regex": [cfg.regex['path_unix']],
            "st": 0.2,
            "depth": 3,
        }
    }
    }

label_pos_dict = {
    "error": ["Src_IP",],
    "auth":["Proto", "Parameters","Actions"],
    "access":["Src_IP","Parameters","Actions","Status"],
    "audit":["PID","Actions", "IOCs", "Status", "Parameters"],
    "dnsmasq":["Parameters", "Actions"],
    # "conn":["Dest_IP", "IOCs","Status"]
}

label_set_dict = {
    "error":
        [
            ["172.17.130.196"], 
        ]
    ,
    "auth":
        [
            ["successful", "www-data"],
            ["opened", "su:session"],
            ["new", "phopkins"],
            ["opened", "system-user:session"],
            ["sudo", "opened"],
            ["sudo", "closed"],
        ]
    ,
    "access":
        [
            ["172.17.130.196"],
            ["10.35.35.206", "200"],
            ["p=5"],
            ["POST"],
            ["wp_meta=WyJpZCJd"],
            ["172.17.130.196","wp_meta=WyJpZCJd"],
            ["172.17.130.196","wp_meta=WyJuZXRzdGF0IiwgIi10Il0%3D"],
            ["172.17.130.196","wp_meta=WyJjYXQiLCAiL2V0Yy9yZXNvbHYuY29uZiJd"],
            ["172.17.130.196","wp_meta=WyJpcCIsICJhZGRyIl0%3D"],
            ["172.17.130.196","wp_meta=WyJwcyIsICItQSJd"],
            ["172.17.130.196","wp_meta=WyJsc2JfcmVsZWFzZSIsICItYSJd"],
            ["172.17.130.196","wp_meta=WyJjYXQiLCAiL2V0Yy9ncm91cCJd"],
            ["172.17.130.196","wp_meta=WyJjYXQiLCAiL2V0Yy9wYXNzd2QiXQ%3D%3D"],
            ["172.17.130.196","wp_meta=WyJkYXRlIl0%3D"],
            ["172.17.130.196","wp_meta=WyJscyIsICItbGFSIiwgIi92YXIvd3d3Il0%3D"],
            ["172.17.130.196","wp_meta=WyJjYXQiLCAiL3Zhci93d3cvaW50cmFuZXQucHJpY2UuZm94Lm9yZy93cC1jb25maWcucGhwIl0%3D"],
            ["172.17.130.196","wp_meta=WyJteXNxbCIsICItdSIsICJ3b3JkcHJlc3MiLCAiLXB0YWlub294M2FlZGVlU2giLCAid29yZHByZXNzX2RiIiwgIi1lIiwgIlwic2VsZWN0ICogZnJvbSB3cF91c2Vyc1wiIl0%3D"],
            ["172.17.130.196","wp_meta=WyJjYXQiLCAiL2V0Yy9wcm9maWxlIl0%3D"],
            ["172.17.130.196","WyJ3Z2V0IiwgImh0dHBzOi8vZ2l0aHViLmNvbS9haXQtYWVjaWQvd3BoYXNoY3JhY2svYXJjaGl2ZS9yZWZzL3RhZ3MvdjAuMS50YXIuZ3oiXQ"],
            ["172.17.130.196","WyJ0YXIiLCAieHZmeiIsICJ2MC4xLnRhci5neiJd"],
            ["172.17.130.196","WyIuL3dwaGFzaGNyYWNrLTAuMS93cGhhc2hjcmFjay5zaCIsICItdyIsICIkUFdEL3JvY2t5b3UudHh0IiwgIi1qIiwgIi4vd3BoYXNoY3JhY2stMC4xL2pvaG4tMS43LjYtanVtYm8tMTItTGludXg2NC9ydW4iLCAiLXUi"],
        ]
    ,
    "audit":
        [
            ["AUTH", "phopkins", "/bin/su", "success"],
            ["USER_CMD", "1001"],
            ["CRED_REFR"],
            ["USER_START"],
            ["USER_END"],
            ["CRED_DISP"],
            ["SYSCALL"],
            ["PROCTITLE"],
            ["consequuntur"],
            ["ACQ", "phopkins", "/bin/su", "success"],
            ["USER_START", "phopkins", "/bin/su", "success"],
            ["AUTH", "phopkins", "/lib/systemd/systemd", "success"],
            ["ACQ", "phopkins", "/lib/systemd/systemd", "success"],
            ["LOGIN", "1001", "1"],
            ["USER_START", "phopkins", "1001", "/lib/systemd/systemd", "success"],
            ["SERVICE_START", "user@1001", "/lib/systemd/systemd", "success"],
        ]
    ,
    "dnsmasq":
        [
            ["ycgjslfptkev.com"],
            ["127.0.0.1", "refused"],
            ["reply", "price.fox.org"],
            ["in-addr.arpa", "172.17.130.196"],
            ["query", "172.17.131.81"],
            ["query", "10.35.35.206"],
            # ["forwarded"],
            # ["reply"],
            # ["cached"],
            ["price.fox.org", "172.17.130.196"],
            ["forwarded","price.fox.org"],
            ["reply","price.fox.org"],
            ["query","intranet.price.fox.org"],
            ["forwarded","intranet.price.fox.org"],
            ["reply","intranet.price.fox.org"],

        ],
    # "conn":[
    #     ["6667"],
    #     ["S0"],
    #     ["167.99.182.238",'SF'],
    #     ['23','S0',"3000"]
    # ]
}

def value_match(ioc_list:list, data:list):
    iocs_num = 0
    for log_string in data:
        for ioc in ioc_list:
            if str(ioc) in str(log_string):
                iocs_num += 1

    return iocs_num


def value_set_match(iocs_list:list, data:list):
    ano_log_num = 0
    for log_string in data:
        for iocs in iocs_list:
            if all( ioc in log_string for ioc in iocs):
                ano_log_num += 1
    return ano_log_num


def iocs_coverage(labelled_data:list, ioc_indicitors:list, check_position:list, 
                  data_type:str):
    ''' calculate iocs coverage for specific log type

    :param labelled_data: the original labelled malicious logs
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
    if data_type == "audit":
        logparser = KVParser(
            indir=indir,
            outdir=outdir,
            log_name='audit.log',
            log_type='audit',
            app='apache',
        )
        logparser.get_output(1)

    elif data_type == "access":
        logparser = ReqParser(
            indir=indir,
            outdir=outdir,
            log_name='access.log',
            log_type='access',
            app='apache',)
        logparser.get_output(1)

    else:
        if data_type in ["auth","error"]:
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
            log_name="{}.log".format(data_type),
            keep_para=True,
            maxChild=100,
        )

        logparser.load_data()
        logparser.parse("{}.log".format(data_type))
        logparser.poi_ext()
        logparser.get_output(1)
    
    # match all the iocs and calculate the coverage
    try:
        uni_df = pd.read_parquet(Path(outdir).joinpath(data_type + ".log_uniform.parquest"))
    except:
        uni_df = pd.read_csv(Path(outdir).joinpath(data_type + ".log_uniform.csv"))

    matched_iocs_num = 0
    for column in check_position:
        matched_iocs_num += value_match(iocs_list, uni_df[column].tolist())
    print(matched_iocs_num)
    print(iocs_num)
    iocs_coverage = round(matched_iocs_num/iocs_num,4)  
    print("iocs coverage for {} is: ".format(data_type, iocs_coverage))

    return iocs_coverage


def label_acc(ano_uniform_df, iocs_set_indicitors:list, match_position: list, 
              data_type:str):
    ''' calculate labelling accuracy for specific log type
    
    :param ano_uniform_df: the unified output
    :param iocs_set_indicitors: the iocs list with embedded iocs set
    :param match_position: the place to match set of iocs, name of iocs locations
    :param data_type: log type
    '''
    match_series = ano_uniform_df[match_position].apply(lambda row: ' '.join(row.values.astype(str)), axis=1).tolist()
    matched_label_num = 0
    matched_label_num = value_set_match(iocs_set_indicitors, match_series)
    lab_acc = round(matched_label_num/len(ano_uniform_df),4)
    print("labelling accuracy for {} is: ".format(data_type, lab_acc))

    return lab_acc
    
def label_csv_data(data_type, label_data_path):
    ''' based on index information in label_data to mark anomaly in uniform_df
    
    :param uniform_df: csv framework with lineId
    '''
    try:
        uni_df = pd.read_parquet(Path(outdir).joinpath(data_type + ".log_uniform.parquest"))
    except:
        uni_df = pd.read_csv(Path(outdir).joinpath(data_type + ".log_uniform.csv"))

    with label_data_path.open("r") as fr:
        data = fr.readlines()
    malicious_lines = []
    
    for line in data:
        log = json.loads(line)
        # consider index starting from 0
        malicious_lines.append(log["line"]-1)
    
    return uni_df.iloc[malicious_lines]
    
# def labelled_data_ext(data_path, label_data_rule_path):
#     '''
#     :param data_path: the file path with malicious data
#     :param label_data_rule_path: the file defining malicious lines
#     '''
#     with data_path.open("r") as fr:
#         data = fr.readlines()

#     malicious_lines = []
    
#     with label_data_rule_path.open("r") as fr:
#         rule_data = fr.readlines()

#     for line in rule_data:
#         log = json.loads(line)
#         # minus one to get index
#         malicious_lines.append(data[log["line"]-1])
    
#     return malicious_lines

if __name__ == "__main__":

    data_type_list = [
                    #   "access",
                    #   "audit", 
                    #   "auth", 
                    #   "error",
                      "dnsmasq",    
                      ]
    
    cur_path = Path.cwd()
    indir = cur_path.joinpath("data").as_posix()
    labdir = cur_path.joinpath("data","label").as_posix()
    outdir = cur_path.joinpath("data","result").as_posix()

    for data_type in data_type_list:
        # load malicious data
        # mal_data = labelled_data_ext(Path(indir).joinpath(f"{data_type}.log"), Path(labdir).joinpath(f"{data_type}.log"))
        with Path(indir).joinpath(f"{data_type}.log").open("r") as fr:
            data = fr.readlines()
        # get the ioc_list
        iocs_list = set()
        for ioc_set in label_set_dict[data_type]:
            iocs_list.update(ioc_set)
        pos_check = label_pos_dict[data_type]
        # print(iocs_coverage(mal_data, list(iocs_list), pos_check, data_type))
        print(iocs_coverage(data, list(iocs_list), pos_check, data_type))

        ano_uni_df = label_csv_data(data_type, Path(labdir).joinpath(f"{data_type}.log"))
        print(label_acc(ano_uni_df, label_set_dict[data_type], label_pos_dict[data_type], data_type))


    