# GraphTrace
Graph based anomaly detection for malware (part of APT)

## Features
- correlate data from multiple sources (network traffic, system/applications/service logs, process execution status)
- extract the entities (obj, sub, action) from events (both structured and unstructured logs)
- cover both logs from Windows and Linux
- correlate processes and build process-specific communities
- graph compression with graph summarization
- distributed graph-based neural network training
- creation of causal and provenance graphs
- graph training with mutiple attributes for nodes and edges


## Explaination of Dataset

- IoT23 (structured logs):
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

- MLog:

    - include:
        - Linux logs /var/log/messages, /var/log/secure 
        - process accounting records /var/log/pacct , other Linux logs
        - Apache web server logs /var/log/httpd/access_log, /var/log/httpd/error-log, /var/log/httpd/referer-log and /var/log/httpd/audit_log 
        - Sendmail /var/log/mailog, 
        - Squid /var/log/squid/access_log, /var/log/squid/store_log, /var/log/squid/cache_log, etc.

- AIT (fox):

    - used for intrusion detection systems, federated learning, alert aggregation

    - include logs from all hosts, apache, error, authentication, DNS/VPN, audit, network traffic, syslog, system monitoring logs

    - ground truth labels for events

    - details:
        - host log: gather/ host name / logs
        - labels directory: labelling information
        - rules directory: how the labels are assigned

- Windows (CBS):
    
    - contain information about component installation, removal or servicing events


## Process Modules

- DNS process
    - log components

        timestamp + service_name[id]: message

    - involving attacks

        wpscan, webshell, dns/network/service scan

    - potential indicitors

        ips/domains, events, commands


## Structure

- entity-extractor：

    - 

## Running

```
# download large language library
python(3) -m spacy download en_core_web_lg
# for rust compiler 
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh


```
 
## References

- EULER: Detecting Network Lateral Movement via Scalable Temporal Link Prediction

- EXTRACTOR: Extracting Attack Behavior from Threat Reports