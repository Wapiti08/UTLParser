'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-22 15:20:48
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-22 15:21:39
 # @ Description: define the node/edge label, features/attributes
 '''

graph_attrs_json = {
    "general": {
        "node": {
            "value": "Parameters",
            "attrs":{}
        },
        "edge":{
            "direc": "Direction",
            "value": "Actions",
            "attrs":{
                "timestamp": "Time",
            }
        },
    },
    "audit": {
        "node": {
            "value": ["Src_IP", "IOCs"],
            "attrs": {}
        },
        "edge":{
            "direc": "Direction",
            "value": "Actions",
            "attrs": {
                "timestamp": "Time",
                "status": "Status"
            },
        }
    },
    "access": {
        "node": {
            "value": ["Src_IP", "Domain"],
            "attrs": {}
        },
        "edge": {
            "direc": "Direction",
            "value": "Actions",
            "attrs": {
                "timestamp": "Time",
                "status": "Status",
                "user_agent": "IOCs",
                "content": "Parameters"
            },
        },
    },
    "process": {
        "option1":{
            "node":{
                "value": ["Src_IP", "Dest_IP"],
                "attrs": {},
            },
            "edge":{
                "direc": "Direction",
                "value": "Proto",
                "attrs": {
                    "timestamp":"Time",
                },
            },
        },
        "option2": {
            "node":{
                "value": ["Src_IP", "IOCs"],
                "attrs":{},
            },
            "edge":{
                "direc": "Direction",
                "value": "Actions",
                "attrs": {
                    "timestamp":"Time",
                }
            },
        },
        "option3": {
            "node":{
                "value": ["Proto", "Actions", "Parameters"],
                "attrs": {},
            },
            "edge":{
                "direc": "Direction",
                "value": "",
                "attrs":{
                    "timestamp": "Time"
                },
            },
        }
    },
    "conn": {
        "node": {
            "value": ["Src_IP", "Dest_IP"],
            "attrs": {
                "port": "IOCs",
            }
        },
        "edge": {
            "direc": "Direction",
            "value": "Proto",
            "attrs": {
                "timestamp": "Time",
                "status": "Status",
                "size": "Parameters"
            }
        }
    }
}

