regex = {
  "ip4": "(?:\d{1,3}\.){3}\d{1,3}",
  "domain": "(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}",
  "ip6": "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
  "ip_with_port": "(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::|\x2F)\d{1,5})",
  "path_unix": "((?<!\w)(\.{1,2})?(?<!\/)(\/((\\\b)|[^ \b%\|:\n\"\\\/])+)+\/?)",
  "path_win": "[A-Za-z]:\\(?:[^\\/:*?'<>|\r\n]+\\)*[^\\/:*?'<>|\r\n]+",
  "port": "(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])",
  "id": "\b\d{1,5}\b"
}

# pre-calcuated log parameters
format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Month> <Date> <Timestamp> <Component>: <Content>",
            # match the domain, ipv4 and ipv6
            "regex": [regex['domain'], regex['ip4'], regex['ip6']],
            "st":0.3,
            # right
            'depth':4,
        },
    },
    "Apache": {
        "auth": {
            "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
            # match the ip, port, id
            "regex": [regex['ip4'],regex['port'],regex['id']],
            "st": 0.33,
            "depth": 4,
        },
        # error is not appliable for automatic format generation
        "error": {
            "log_format": "\[<Week> <Month> <Day> <Timestamp> <Year>\] \[<Proto>\] \[pid <PID>\] \[client <Src_IP>\] <Content>",
            # match the path, port, id
            "regex": [regex['path_unix']],
            "st": 0.2,
            "depth": 3,
        },
        # "access": {
        #     "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
        #     # match the ip, port, id
        #     "regex": [config.regex['ip4'],config.regex['port'],config.regex['id']],
        #     "st": 0.7,
        #     "depth": 4,
        # },
    },
    "Linux": {
        "syslog":{
            "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
            # match path
            "regex": [regex['path_unix'],regex['domain']],
            "st": 0.2,
            "depth":6,
        }
    },
    "Sysdig": {
        "process":{
            "log_format": "<Month> <Day> <Timestamp> <Component>: <Content>",
            # match path
            "regex": [regex['path_unix']],
            "st": 0.7,
            "depth":5,
        }
    }

}

log_type = {
  # major key-value pairs as the content
  "kv": ["audit", "process"],
  # http request structure
  "req": ["access"],
  "str": ["conn"],
  "gen": ["auth", "syslog", "dns", "error"]
}


dep_map_dict = {
    "<Month>": ["<Day>"],
    "<Day>":["<Timestamp>"],
    "<Timestamp>":["<Level>", "<Component>", "<Proto>"],
    "<Component>":["<Proto>","<Application>","<Level>"],
    "<Level>":["Proto"],
    "<Proto>": ["[<PID>]", "<Content>",":"],
    ":":["<Content>"],
    "[<PID>]": [":"]
}

pos_com_mapping = {
    0: ["<Month>", "<Date>"],
    1: ["<Day>", "<Timestamp>"],
    2: ["<Timestamp>"],
    3: ["<Component>","<Proto>","<Level>","<Application>"]
}

# define the direct points of interest from key names or components
POI = {
  "apache": {
    "audit": ["type", "timestamp", "acct", "exe", "hostname", "res", "pid", "unit"],
    "access": ["Src_IP", "Time", "Content", "Status", "Referer", "Request_Method", "User_Agent"]
  },
  "sysdig":{ 
    "process": ["timestamp", "proc", "pid", "event_type", "src_ip", "dest_ip","fd", "path", "sub_event"]
  },
  "zeek": {
    "conn": ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "resp_bytes", "conn_state", "service"],
  }
}

format={
  "process": {
    # for testing 
    "sysdig": "<Timestamp> <CPU> <Proc> \(<PID>\) <Dir> <Args>",
    # correct one
    # sysdig: "<Evt_Num> <Date> <CPU> <Proc> \(<PID>\) <Dir> <Event_Type> <Args>"
  }
}


# from node/edge attribute to iocs locations
attr_iocs_dict = {
    "node": {
        "value": ["Src_IP","IOCs", "Dest_IP"],
        "attrs": ["IOCs"]
    },
    "edge": {
        "value": ["Actions"],
        "attrs": ["Status", "IOCs"],
    }
}

# give example of labels in conn
iot_ioc_dict = {
        "Status":["S0"],
        "IOCs":[80, 8081, 52869,37215,666],
        "Dest_IP":["172.32.33.171"]
}

# example of iocs
ait_iot_dict = {
    "Src_IP": ["172.17.130.196", "10.35.35.206"],
    "Proto": ["su","system-user"],
    "Parameters": ["phopkins", "p=5", 
                   "wp_meta=WyJpZCJd",
                   "wp_meta=WyJpZCJd",
                   "wp_meta=WyJjYXQiLCAiL2V0Yy9yZXNvbHYuY29uZiJd",
                   "wp_meta=WyJpcCIsICJhZGRyIl0%3D"],
    "Actions": ["opened", "closed", "POST","AUTH","CRED_REFR","USER_START"],
    "Status": [200],
    "IOCs": ["phopkins","/lib/systemd/systemd"]
}

# define the potential candidates to decide optimal time delay
time_thres_list = [0,1,2,3,4]

# define the average path length inside temporal graph
avg_len = 1
