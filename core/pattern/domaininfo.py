'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-18 09:53:03
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-18 09:54:30
 # @ Description: the mapping dict from uniform format to specific components,
                used to define the graph rules
 '''

# define the mapping from uniformed column to components for unstructured logs

unstru_log_poi_map = {
    "apache": {
        # audit log ---- key-value pairs
        "audit": {
                    "Time": "timestamp",
                    "Actions":"type",
                    # only accept two elements to form a tuple
                    "IOCs":["acct","exe"],
                    "Status":"res",
                    "Direction":"->"
                },
        # access log ---- request log
        "access":{
                    "Time": "Time",
                    "Src_IP": "Src_IP",
                    "Domain": "Referer",
                    "Parameters": "Content",
                    "Actions": "Request_Method",
                    "Status": "Status",
                    "IOCs": "User_Agent",
                    "Direction":"->"
                }
            },
    "sysdig": {
        "process": {
                "Time": "time",
                # if exist in fd
                "Src_IP": "src_ip",
                # if exist in fd
                "Dest_IP":"dest_ip",
                # same as the process name
                "Proto":"process",
                # if exists
                "Parameters": "sub_event",
                "IOCs":["fd", "path"],
                "PID": "pid",
                "Actions":"type",
                "Direction":"->",
        }

               },
    "general": {
            "Time": "Time",
            "Parameters": "Parameters",
            "Actions": "Content",
            "Direction": 'Direction'
            }

                }


# define the mapping from uniformed column to components for structured logs (zeek)
## classified with log type
stru_log_poi_map = {
    "conn": {
        "Time": "ts",
        "Src_IP": "id.orig_h",
        "Dest_IP": "id.resp_h",
        "Proto": "service",
        "Parameters": "resp_bytes",
        "IOCs": ["id.orig_p", "id.resp_p"],
        "Status": "conn_state",
        "Direction": "->"
    }
}