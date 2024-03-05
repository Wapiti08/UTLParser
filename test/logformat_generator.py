import calendar
import re

short_month_name = calendar.month_abbr[1:]
month_regex = "|".join(short_month_name)
form_month_regex = r"(\b(" + month_regex + r")\b)"

day_regex = r'\b(?:0[1-9]|[12][0-9]|3[01])\b'
timestamp_regex = r'\d{2}:\d{2}:\d{2}'
date_regex=r'\d{4}-\d{2}-\d{2}'

level = "info|warn|error"

# test_logs = {
#     "Jan 15 10:02:51 dnsmasq[14522]: query[AAAA] dualstack.com.imgix.map.fastly.net from 10.35.35.118",
#     "Jan 15 10:02:51 dnsmasq[14522]: forwarded dualstack.com.imgix.map.fastly.net to 192.168.255.254",
#     "Jan 15 10:02:51 dnsmasq[14522]: reply previews.customer.envatousercontent.com is 99.86.237.61",
#     "Jan 15 10:02:52 dnsmasq[14522]: query[AAAA] tls12.newrelic.com.cdn.cloudflare.net from 10.35.35.118",
#     "Jan 15 10:02:52 dnsmasq[14522]: forwarded dh4oiqg45nvw7.cloudfront.net to 192.168.255.254"
# }

test_logs_1 = {
    "Jan 17 17:55:29 intranet-server sshd[13953]: pam_unix(sshd:session): session closed for user hwarren",
    "Jan 17 17:55:29 intranet-server systemd-logind[1011]: Removed session 98."
}

dep_map_dict = {
    "<Month>": ["<Day>"],
    "<Day>":["<Timestamp>"],
    "<Timestamp>":["<Level>", "<Component>","<Proto>"],
    "<Component>":["<Proto>"],
    ":":["<Content>"],
    "<Component>":["[<PID>]","<Content>"],
    "<Proto>": ["[<PID>]", "<Content>"],
    "[<PID>]": [":"]
}

pos_com_mapping = {
    0: ["<Month>", "<Date>", "<>"],
    1: ["<Day>", "<Timestamp>"],
    2: ["<Timestamp>"],
    3: ["<Component>","<Proto>","<Application>"]
}

component_pool = [
    "<Timestamp>",
    "<Day>",
    "<Month>",
    "<Date>",
    "<Content>",
    "<Level>",
    "<Component>",
    "[<PID>]",
    "<Proto>",'<Application>'
]

remain_chars = [
    '-','',',','"',"[","]","(",")"
]

com_rex_mapping = {
    "<Month>":[form_month_regex],
    "<Day>":[day_regex],
    "<Date>":[date_regex],
    "<Timestamp>": [timestamp_regex],
    "<Component>":[r'^[a-zA-Z].*'],
    "<Proto>":[r'^.*?(?=\[|:)'],
    "<Application>":[r'^.*?(?=\[|:)'],
    "<Level>":[level],
    "[<PID>]":[r'^\d+$',r'\b\d+\b'],
}

    

def com_check(sentence:str, pos:int, stop_indictor:str, split_num:int, log_format_dict:dict):
    ''' identify the components according to the regex matching
    
    '''
    # split sentence by first space first
    tokens = sentence.split(" ",split_num)
    log_format_dict[pos] = []
    # only check ending ":"
    if not tokens[0].endswith(stop_indictor):
        for com_name, regex_list in com_rex_mapping.items():
            print("matching {}".format(tokens[0]))
            matched = [re.search(regex, tokens[0]) for regex in regex_list]
            print(matched)
            if any(item is not None for item in matched):
                log_format_dict[pos].append(com_name)
                print("current log format dict is:", log_format_dict)

        if len(log_format_dict[pos]) == 0:
            # if no any match, need to add new regex
            print("need to add new regex to match: {}".format(tokens[0]))
            return
        else:
            pos += 1
            return com_check(tokens[1], pos, stop_indictor, split_num, log_format_dict)
            
    else:
        # check the component of first part
        ## remove the stop indicitor part
        token_no_indicitor = tokens[0].replace(stop_indictor,"")
        print("replacing token from {} to {}".format(tokens[0], token_no_indicitor))
        # add the stop indictor as the middle component
        log_format_dict[pos+1] = [":"]
        # add default second part as the content
        log_format_dict[pos+2] = ["<Content>"]
        for com_name, regex_list in com_rex_mapping.items():
            matched = [re.search(regex, token_no_indicitor) for regex in regex_list]
            if any(item is not None for item in matched):
                # check whether com_name has exsited in pos
                if com_name in log_format_dict[pos]:
                    continue
                else:
                    log_format_dict[pos].append(com_name)
                    print("current log format dict is:", log_format_dict)

        if len(log_format_dict[pos]) == 0:
            # if no any match, need to add new regex
            print("need to add new regex to match: {}".format(tokens[0]))
            return

    return log_format_dict


def pos_check(pos_com_mapping, maybe_log_format_dict):
    ''' reduce noise and build the graph according to neigh_mapping_dict
    
    '''
    log_format_dict = {}
    # check the position scope
    for pos, com_list in maybe_log_format_dict.items():
        if pos <= (len(pos_com_mapping) - 1):
            maybe_log_format_dict[pos] = list(set(com_list) & set(pos_com_mapping[pos]))
        else:
            break


    log_format_dict = maybe_log_format_dict
    return log_format_dict

def dep_check(dep_map_dict, maybe_log_format_dict):
    # check the dependency pattern
    log_format_dict = {}
    for pos, com_list in maybe_log_format_dict.items():
        if pos != len(maybe_log_format_dict) - 1:
            cur_com = com_list[0]
            if cur_com in dep_map_dict:
                print("checking dependency for {}".format(cur_com))
                deps = dep_map_dict[cur_com]
                # Filter out any incorrect components from the component_list
                correct_components = [comp for comp in maybe_log_format_dict[pos+1] if comp in deps]
                print("right child is {}".format(correct_components))
                # there is right match and not remove
                if len(correct_components)>0 & len(correct_components) == maybe_log_format_dict[pos+1]:
                    # Update the component_list with correct components
                    continue
                # remove wrong prediction then replace with right dependent component
                elif len(correct_components) != maybe_log_format_dict[pos+1]:
                    maybe_log_format_dict[pos+1] = correct_components
        
    log_format_dict = maybe_log_format_dict
    return log_format_dict

def format_ext(log_format_dict:dict):
    ''' extract the shortest path and format log format
    
    '''
    # choose the shorted path


    # format the log format to match the log parser
    com_list = list(log_format_dict.values())
    com_list = [com[0] for com in com_list]
    log_format = " ".join(com_list)

    # remove the space between component and PID
    # remove the space between PID and :
    log_format = re.sub(r'(<Component>)\s+(\[<PID>\])', r'\1\2', log_format)
    # Replace space between [<PID>] and :
    log_format = re.sub(r'(\[<PID>\])\s+(:)', r'\1\2', log_format)

    if "[" in log_format:
        log_format = log_format.replace("[","\[")
        log_format = log_format.replace("]","\]")

    return log_format
    


for sentence in test_logs_1:
    print("generating log format for: \n {}".format(sentence))
    log_format_dict = {}
    stop_indictor = ":"
    split_num = 1
    pos = 0
    update_log_format_dict = com_check(sentence, pos, stop_indictor, split_num, log_format_dict)    
    print("the potential format dict is: \n {}".format(update_log_format_dict))
    log_format_dict_right_pos = pos_check(pos_com_mapping, update_log_format_dict)
    print("matched log format in right position: {}".format(log_format_dict_right_pos))
    log_format_dict = dep_check(dep_map_dict, log_format_dict_right_pos)
    print("matched right format dict is: {}".format(log_format_dict))
    print("generated log format is: {}".format(format_ext(log_format_dict)))

