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

def iocs_coverage(labelled_data, ioc_indicitors:list, check_position:list, data_type:str):
    ''' calculate iocs coverage for specific log type

    :param labelled_data: the original malicious logs
    :param ioc_indicitors: the list of ioc element
    :param check_position: the place to match iocs
    :param data_type: log type
    '''
    iocs_num = 0
    # extract all iocs according to ioc_indicitors
    for log_string in labelled_data:
        if any(threat in log_string for threat in ioc_indicitors):
            iocs_num += 1

    # parse labelled logs into uniformed csv
    if data_type == "conn":
        logparser = StrLogParser()
    
    elif data_type == "audit":
        logparser = KVParser()
    
    elif data_type == "access":
        logparser = ReqParser()

    else:
        logparser = GenLogParser()

    # match all the iocs and calculate the coverage



def label_acc(uniform_csv, iocs_set_indicitors:list, match_position: list, data_type:str):
    ''' calculate labelling accuracy for specific log type
    
    :param uniform_csv: the unified output
    :param iocs_set_indicitors: the iocs list with embedded iocs set
    :param match_position: the place to match set of iocs
    :param data_type: log type
    '''
    

    