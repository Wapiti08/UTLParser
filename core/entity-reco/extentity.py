""" 
@Description: module to extract potential user names, process, event from unified output
@Author: newt.tan 
@Date: 2024-01-23 14:58:04 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-01-23 14:58:04  
"""

from pathlib import Path
import pandas as pd
from ast import literal_eval

def user_entity_ext(indir_list:list, outdir:str):
    ''' extract possible user names from possible locations
    first element of parameters in audit logs

    
    '''
    user_list = []
    for indir in indir_list:
        df = pd.read_csv(indir)
        df["Parameters"] = df["Parameters"].apply(literal_eval)
        user_list.extend([parameter[0] for parameter in df["Parameters"].tolist()])
    # filter '-'
    user_list = list(filter(lambda x: x!='-', user_list))
    # remove repetitions
    user_list = list(set(user_list))
    print(user_list)
    with outdir.open('w') as fw:
        for user in user_list:
            fw.write(user + '\n')


def process_entity_ext(indir_list:list, outdir:str):
    ''' extract possible process names from possible locations
    proto element in auth logs, error logs, process logs
    '''
    process_list = []
    for indir in indir_list:
        df = pd.read_csv(indir)
        process_list.extend(df["Proto"].tolist())

    process_list = list(filter(lambda x: x!='-', process_list))
    # remove repetitions
    process_list = list(set(process_list))
    print(process_list)
    with outdir.open('w') as fw:
        for user in process_list:
            fw.write(user + '\n')


def event_entity_ext(indir_list:list, outdir:str):
    ''' extract possible event names from possible locations
    parameters, actions in process logs
    '''
    event_list = []
    for indir in indir_list:
        df = pd.read_csv(indir)
        event_list.extend(df["Parameters"].tolist())
        event_list.extend(df["Actions"].tolist())

    event_list = list(filter(lambda x: x!='-', event_list))
    # remove repetitions
    event_list = list(set(event_list))
    print(event_list)
    with outdir.open('w') as fw:
        for user in event_list:
            fw.write(user + '\n')


if __name__ == "__main__":
    cur_path = Path.cwd()
    pro_path = cur_path.parent.parent
    indir = pro_path.joinpath("unit_test","data","result")
    outdir = cur_path

    user_file_list = ["audit.log_uniform.csv"]
    user_indir_list = [indir.joinpath(file).as_posix() for file in user_file_list]
    user_entity_ext(user_indir_list, outdir.joinpath("user_entity.txt").as_posix())

    event_file_list = ["process.log_uniform.csv"]
    event_indir_list = [indir.joinpath(file).as_posix() for file in event_file_list]
    event_entity_ext(event_indir_list, outdir.joinpath("event_entity.txt").as_posix())

    process_file_list = ["auth.log_uniform.csv","error.log_uniform.csv","process.log_uniform.csv"]
    process_indir_list = [indir.joinpath(file).as_posix() for file in process_file_list]
    process_entity_ext(process_indir_list, outdir.joinpath("process_entity.txt").as_posix())