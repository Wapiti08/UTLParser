import calendar
import re

short_month_name = calendar.month_abbr[1:]
month_regex = "|".join(short_month_name)
form_month_regex = r"(\b(" + month_regex + r")\b)"

day_regex = r'\b(?:0[1-9]|[12][0-9]|3[01])\b'
timestamp_regex = r'\d{2}:\d{2}:\d{2}'
date_regex=r'\d{4}-\d{2}-\d{2}'

level = "info|warn|error"

test_logs = {
    "Jan 15 10:02:51 dnsmasq[14522]: query[AAAA] dualstack.com.imgix.map.fastly.net from 10.35.35.118",
    "Jan 15 10:02:51 dnsmasq[14522]: forwarded dualstack.com.imgix.map.fastly.net to 192.168.255.254",
    "Jan 15 10:02:51 dnsmasq[14522]: reply previews.customer.envatousercontent.com is 99.86.237.61",
    "Jan 15 10:02:52 dnsmasq[14522]: query[AAAA] tls12.newrelic.com.cdn.cloudflare.net from 10.35.35.118",
    "Jan 15 10:02:52 dnsmasq[14522]: forwarded dh4oiqg45nvw7.cloudfront.net to 192.168.255.254"
}

test_logs_1 = {
    "Jan 17 17:55:29 intranet-server sshd[13953]: pam_unix(sshd:session): session closed for user hwarren",
    "Jan 17 17:55:29 intranet-server systemd-logind[1011]: Removed session 98."
}

neigh_mapping = {
    "<Month>": ["<Day>"],
    "<Day>":["<Timestamp>"],
    "<Timestamp>":["Level", "Component"],
    ":":["<Content>"],
    "<Component>":["\[<PID>\]"],
    "<Proto>": ["\[<PID>\]"]
}

pos_com_mapping = {
    0: ["<Month>", "<Date>", "<>"],
    1: ["<Day>", "<Timestamp>"],
    2: ["<Component>",",","<Timestamp>"]
}

component_pool = [
    "<Timestamp>",
    "<Day>",
    "<Month>",
    "<Date>",
    "<Content>",
    "<Level>",
    "<Component>",
    "<PID>"
]

remain_chars = [
    '-','',',','"',"[","]","(",")"
]

com_rex_mapping = {
    "<Month>":[form_month_regex],
    "<Day>":[day_regex],
    "<Date>":[date_regex],
    "<TimeStamp>": [timestamp_regex],
    "<Component>":[r'^[a-zA-Z].*'],
    "<Level>":[level],
    "<Content>":[],
    "<PID>":[r'^\d+$'],
}

    

def com_check(sentence:str, pos:int, stop_indictor:str, split_num:int, log_format_dict:dict):
    ''' identify the components according to the regex matching
    
    '''
    # split sentence by first space first
    tokens = sentence.split(" ",split_num)
    log_format_dict[pos] = []
    if stop_indictor not in tokens[0]:
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


def format_graph(pos_com_mapping, maybe_log_format_dict):
    ''' reduce noise and build the graph according to neigh_mapping_dict
    
    '''
    log_format_dict = {}
    for pos, com_list in maybe_log_format_dict.items():
        if pos <= (len(pos_com_mapping) - 1):
            maybe_log_format_dict[pos] = list(set(com_list) & set(pos_com_mapping[pos]))
        else:
            break
    log_format_dict = maybe_log_format_dict
    return log_format_dict

def format_ext():
    ''' extract the shortest path as the log format --- more general
    
    '''
    pass


for sentence in test_logs:
    log_format_dict = {}
    stop_indictor = ":"
    split_num = 1
    pos = 0
    update_log_format_dict = com_check(sentence, pos, stop_indictor, split_num, log_format_dict)    
    print("generating log format for: \n {}".format(sentence))
    print("the potential format dict is: \n {}".format(update_log_format_dict))
    print("matched right format dict is: {}".format(format_graph(pos_com_mapping, update_log_format_dict)))