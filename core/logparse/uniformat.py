'''
    automatically generate the suitable format for following log parsing

    generate regex:
        domain: \b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b
        ipv4: \b(?:\d{1,3}\.){3}\d{1,3}\b
        ipv4 with port: \b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b
        ipv6: \b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b
        request parameter: \?[^\s]+
'''
import spacy
import nltk
import flair

# the matching format for unstructured logs
format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Month> <Date> <Time> dnsmasq\[<PID>\]: <Content>",
            # match the domain, ipv4 and ipv6
            "regex": [r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", r"\b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"],
            "st":0.7,
            "depth":4,
            # filter for domain name match with general domain extension
            "filter": 1,
            "iocs":0,
        },
    },
    "Apache": {
        "org-access": {
            # "log_format": "<SRC_IP> - - \[<Time>\] \"<Request_Method> <Content> <HTTP_Version>\" <Status_Code> <Response_Size> \"<Referer>\" \"<User_Agent>\"",
            "log_format": "<SRC_IP> - - \[<Time>\] \"<Request_Method> <Content> <HTTP_Version>\" <Status_Code> <Response_Size> \"<Referer>\" \"<User_Agent>\"",
            # match the parameter part
            "regex": [r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r"\?[^\s]+"],
            "st": 0.8,
            "depth": 5,
            "filter":0,
            "iocs":0,
        },
        "audit": {
            # "log_format": "type=<Type> msg=audit\(<Time>\): pid=<PID> uid=<UID> auid=<AUID> ses=<SES> msg=\'unit=<Unit> comm=<Comm> exe=<Exe> hostname=<HostName> addr=<Addr> terminal=<Terminal> res=<Res>\'",
            # "log_format": "type=<Type> msg=audit\(<Time>\): pid=<PID> uid=<UID> auid=<AUID> ses=<SES> msg=\'<Content>\'",
            "log_format": "type=<Type> msg=audit\(<Time>\): <Content>",
            "regex": [r"\/(?:[\w-]+\/)+[\w-]+"],
            "st":0.8,
            "depth": 6,
            "filter":1,
            "iocs":1,
        },
        "auth": {
            "log_format": "<Month> <Date> <Time> <Component> <Level>: <Content>",
            "regex": [],
            "st": 0.6,
            "depth": 4,
            "filter": 0,
            "iocs":0,
        },
    "Process": {
        "sysdig": {
            "log_format": "<Time> <CPU_ID> <Command> \(<Threat_ID>\) <Event_Direction> <Type> <Arguments>",
            "regex": [r"\/(?:[\w-]+\/)+[\w-]+", r"\b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b"],
            "st": 0.7,
            "depth": 4,
            "filter": 0,
            "iocs": 1,
            },
        },
    }
}