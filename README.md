# UTLParser
![Python](https://img.shields.io/badge/Python3-3.10-brightgreen.svg) 
![License](https://img.shields.io/badge/license-MIT3.0-green.svg)
![Testing Environment](https://img.shields.io/badge/macOS-14.2.1-golden.svg)
<!-- [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.13918585.svg)](https://doi.org/10.5281/zenodo.13918585) -->

---

Unified Semantic Log Parsing and Causal Graph Construction for Attack Attribution

## Features
- correlate data from multiple sources (network traffic, system/applications/service logs, process execution status)
- automatically recognize log format, and calculate depth and similarity threshold
- extract the entities (obj, sub, action) with depedency relationships from events (both structured and unstructured logs) 
- provenance graph construction from multi-source logs
- measure the delay for log fusion
- interfaces for optimized temporal graph query and graph community detection


## Structure
- core: 
    - entity_reco: custom entity extraction from unifited output

    - graph_create: the module block to build causal graphs

    - graph_label: labelling temporal graph

    - logparse: multiple log parsers

    - pattern: the rule to build unifited output and graph

- eval: benchmark testing

- eval_data: the code to generate evaluation data

- src: the running main interface

- unit_test: the unit testing for core modules

- utils: util functions to support processing

- config: the config file including regexes, defined poi, etc

## Running

- preprepration
```
# avoid python version conflict --- pyenv
brew install pyenv-virtualenv
brew install pyenv
pyenv install 3.10
pyenv global 3.10
pyenv virtualenv 3.10 UTLParser
# activate the environment
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"
pyenv local UTLParser
pyenv activate UTLParser
pip3 install -r requirements.txt
# download large language library
python -m spacy download en_core_web_lg
```

- how to use
```
# enter into the src folder where main.py locates

# single log source processing -- under src folder
python3 main.py -a dns -i dns.log

# multiple log sources processing --- fused graph
python3 main.py -f True -al 'dns,error,access,audit'

# temporal graph query
python3 main.py -al 'dns,error,access,audit' -t "2022-Jan-15 10:17:01.246000"

# assign labels to fused graphs
python3 main.py -l True 

```

- custom running

    - add poi and iocs for custom logs inside config.py
    - repeat above steps

## Output Format

- IOCs:

    Timestamp, Src_IP, Dst_IP, Proto or Application, Domain, PacketSize, ParaPair (tuple)

## Explaination of Dataset

- AIT (fox) --- pure unstructured logs:

    - used for intrusion detection systems, federated learning, alert aggregation

    - include logs from all hosts, apache, error, authentication, DNS/VPN, audit, network traffic, syslog, system monitoring logs

    - ground truth labels for events

    - details:
        - host log: gather/ host name / logs
        - labels directory: labelling information
        - rules directory: how the labels are assigned

    - launched attacks:
        - Scans
        - Webshell upload --- apache
        - password cracking
        - privilege escalation --- dnsmasq, apache, audit (internal_server), system.cpu
        - remote command execution --- dnsmasq,apache, audit (internal_server), system.cpu
        - data exfiltration --- dnsmasq, audit (internal_share), 

- Sysdig Process:
    ```
    # follow the format like: evt.num, evt.time, evt.cpu, proc.name, thread.tid, evt.dir, evt.type, evt.args
    - 123 23:40:09.105899621 3 httpd (28599) > switch next=0 pgft_maj=3 pgft_min=619 vm_size=442720 vm_rss=668 vm_swap=7004
    ```

- IoT23 (structured logs) --- network traffic:
    - label information
        - attack (part of APT):
            indictors that there was some type of attack from the infected device to another host
        - C & C (part of APT):
            the infected device was connnected to a CC server
        - DDoS:
            ddos attack is being executed by the infected device
        - FileDownload (part of APT):
            a file is being downloaded to the infected device
        - HeartBeat (periodic similar connections)
            packets sent on this connection are used to keep a track on the infected host 
        - Mirai (botnet)
            similar patterns
        - Okiru (botnet)
            same parameters
        - PortScan (part of APT)
        - Torii (botnet)
            same parameters

    - related field and its number
        - id.resp_h (5) ----> C & C
        - id.resp_p (6) ----> Malware, HeartBeat, Port Scan
        - conn_state (12) ----> Port Scan

    - choosen fields to extract features
        - ts? -- time series --- dynamic beyasian network
        - id.orig_h, id.orig_p, id.resp_h, id.resp_p
        - resp_bytes ---- filedownload
        - conn_state ---- port scan
        - feature analysis? --- other features


## Next Plan

- Build Temporal Graph Neural Networks

    - reduce the graph size to some extent: suitable for low-memory cost training
    - capable of process heterogeneous graph attributes
    - capable of capture the changes between temporal graphs
    - capable of measuring normal and abnormal behaviour in unsupervised way
