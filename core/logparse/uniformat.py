'''
    automatically generate the suitable format for following log parsing

    generate regex:
        domain: \b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b
        ipv4: \b(?:\d{1,3}\.){3}\d{1,3}\b
        ipv4 with port: \b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b
        ipv6: \b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b
        request parameter: \?[^\s]+
    
        
    process format:
        %evt.num %evt.time %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args

'''
import spacy
import nltk
import flair
import random

# the matching format for unstructured logs
# format_dict = {
#     "DNS": {
#         "dnsmasq": {
#             "log_format": "<Month> <Date> <Time> dnsmasq\[<PID>\]: <Content>",
#             # match the domain, ipv4 and ipv6
#             "regex": [r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", r"\b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"],
#             "st":0.7,
#             "depth":4,
#             # filter for domain name match with general domain extension
#             "filter": 1,
#             "iocs":0,
#         },
#     },
#     "Apache": {
#         "org-access": {
#             # "log_format": "<SRC_IP> - - \[<Time>\] \"<Request_Method> <Content> <HTTP_Version>\" <Status_Code> <Response_Size> \"<Referer>\" \"<User_Agent>\"",
#             "log_format": "<SRC_IP> - - \[<Time>\] \"<Request_Method> <Content> <HTTP_Version>\" <Status_Code> <Response_Size> \"<Referer>\" \"<User_Agent>\"",
#             # match the parameter part
#             "regex": [r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r"\?[^\s]+"],
#             "st": 0.8,
#             "depth": 5,
#             "filter":0,
#             "iocs":0,
#         },
#         "audit": {
#             # "log_format": "type=<Type> msg=audit\(<Time>\): pid=<PID> uid=<UID> auid=<AUID> ses=<SES> msg=\'unit=<Unit> comm=<Comm> exe=<Exe> hostname=<HostName> addr=<Addr> terminal=<Terminal> res=<Res>\'",
#             # "log_format": "type=<Type> msg=audit\(<Time>\): pid=<PID> uid=<UID> auid=<AUID> ses=<SES> msg=\'<Content>\'",
#             "log_format": "type=<Type> msg=audit\(<Time>\): <Content>",
#             "regex": [r"\/(?:[\w-]+\/)+[\w-]+"],
#             "st":0.8,
#             "depth": 6,
#             "filter":1,
#             "iocs":1,
#         },
#         "auth": {
#             "log_format": "<Month> <Date> <Time> <Component> <Level>: <Content>",
#             "regex": [],
#             "st": 0.6,
#             "depth": 4,
#             "filter": 0,
#             "iocs":0,
#         },
#     "Process": {
#         "sysdig": {
#             "log_format": "<Time> <CPU_ID> <Command> \(<Threat_ID>\) <Event_Direction> <Type> <Arguments>",
#             "regex": [r"\/(?:[\w-]+\/)+[\w-]+", r"\b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b"],
#             "st": 0.7,
#             "depth": 4,
#             "filter": 0,
#             "iocs": 1,
#             },
#         },
#     }
# }


# the matching format for unstructured logs
# format_dict = {
#     "DNS": {
#         "dnsmasq": {
#             "log_format": "<Month> <Date> <Time> dnsmasq\[<PID>\]: <Content>",
#             # match the domain, ipv4 and ipv6
#             "regex": [r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", r"\b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"],
#             "st":0.7,
#             "depth":4,
#             # filter for domain name match with general domain extension
#             "filter": 1,
#             "iocs":0,
#         },
#     },
#     "Apache": {
#         "auth": {
#             "log_format": "<Month> <Date> <Time> <Component> <Level>: <Content>",
#             "regex": [],
#             "st": 0.6,
#             "depth": 4,
#             "filter": 0,
#             "iocs":0,
#         },

#     }
# }


# iocs_rex_mapping = {
#     "domain": "\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
#     "ipv4": "\b(?:\d{1,3}\.){3}\d{1,3}\b",
#     "ipv4 with port": "\b(?:\d{1,3}\.){3}\d{1,3}[#\d+]+\b",
#     "ipv6": "\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
#     "request parameter": "\?[^\s]+",
# }

# com_rex_mapping = {
#     "<Month>":
#     "<Date>":
#     "<Time>":
#     "<Component>":
#     "<Level>":
#     "<Content>":
# }

class ComNode:
    def __init__(self, component_type, value=None):
        self.component_type = component_type
        self.value = value
        self.children = []

    def add_child(self, child):
        self.children.append(child)

    def __repr__(self):
        return f"{self.component_type}: {self.value}"


def parse_log(log):
    root = ComNode("Log")
    current_node = root

    components = log.split()
    for component in components:
        if component.startswith("[") and component.endswith("]"):
            component_type = "Timestamp"
            value = component.strip("[]")
        elif "=" in component:
            component_type = "Key-Value"
            key, value = component.split("=", 1)
            current_node.add_child(ComNode("Key", key))
            current_node.add_child(ComNode("Value", value))
            continue  # Skip adding this component as a node
        else:
            component_type = "Text"
            value = component

        new_node = ComNode(component_type, value)
        current_node.add_child(new_node)
        current_node = new_node

    return root


def print_log_tree(node, indent=0):
    print("  " * indent + str(node))
    for child in node.children:
        print_log_tree(child, indent + 1)


# Example log
log = "10.35.35.118 - - [19/Jan/2022:08:41:07 +0000] \"POST /wp-admin/admin-ajax.php HTTP/1.1\" 200 1168 \"https://intranet.price.fox.org/wp-admin/edit.php\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0\""

# Parse the log and print the tree structure
log_tree = parse_log(log)
print_log_tree(log_tree)

from collections import defaultdict

class Graph:
    def __init__(self):
        self.graph = defaultdict(list)

    def add_edge(self, u, v):
        self.graph[u].append(v)

    def dfs(self, start_node, visited, sequence):
        visited.add(start_node)
        sequence.append(start_node)
        for neighbor in self.graph[start_node]:
            if neighbor not in visited:
                self.dfs(neighbor, visited, sequence)

# Example usage:
g = Graph()
g.add_edge("<Timestamp>", "Month")
g.add_edge("Timestamp", "Day")
g.add_edge("Month", "Content")
g.add_edge("Day", "Content")

visited = set()
sequence = []
g.dfs("Timestamp", visited, sequence)
print("General sequential components:", sequence)