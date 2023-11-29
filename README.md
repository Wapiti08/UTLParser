# GraphTrace
Graph based anomaly detection for malware (part of APT)

## Features
- correlate host logs and http traffic to precisely locate anomaly behaviours

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

## Running

```
python(3) -m spacy download en_core_web_sm

```
 
## References

- EULER: Detecting Network Lateral Movement via Scalable Temporal Link Prediction

- HTTP-Based APT Malware Infection Detection Using URL Correlation Analysis
