regex = {
  "ip4": "\b(?:\d{1,3}\.){3}\d{1,3}\b",
  "domain": "\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
  "ip6": "\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
  "ip_with_port": "\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::|\x2F)\d{1,5})\b",
  "path_unix": "\/(?:[^\/]+\/)*[^\/]+\.[^\/]+",
  "path_win": "[A-Za-z]:\\(?:[^\\/:*?'<>|\r\n]+\\)*[^\\/:*?'<>|\r\n]+",
  "port": "\b(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\b",
  "id": "\b\d{1,5}\b"
}


log_type = {
  "kv": ["audit", "process"],
  "req": ["access"],
  "gen": ["auth", "linux", "dns"]
}

POI = {
  "apache": {
    "audit": ["type", "timestamp", "acct", "exe", "res"],
    "access": ["Src_IP", "Timestamp", "Parameters", "Status", "Actions"]
  },
  "sysdig":{ 
    "process": ["time", "proc", "pid", "event_type", "fd", "path"]
  },
  "zeek": {
    "conn": ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "resp_bytes", "conn_state"],
  }
}

format={
  "process": {
    # for testing 
    "sysdig": "<Date> <CPU> <Proc> \(<PID>\) <Dir> <Event_Type> <Args>",
    # correct one
    # sysdig: "<Evt_Num> <Date> <CPU> <Proc> \(<PID>\) <Dir> <Event_Type> <Args>"
  }
}