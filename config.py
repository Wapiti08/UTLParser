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


log_type = {
  "kv": ["audit", "process"],
  "req": ["access"],
  "gen": ["auth", "syslog", "dns"]
}

# define the direct points of interest from key names or components
POI = {
  "apache": {
    "audit": ["type", "timestamp", "acct", "exe", "res"],
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