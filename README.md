# GraphTrace
Graph based anomaly detection for malware (part of APT)

## Features
- correlate host logs and http traffic to precisely locate anomaly behaviours

## Explaination of Dataset

- IoT23:
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



 
## References

- EULER: Detecting Network Lateral Movement via Scalable Temporal Link Prediction

- HTTP-Based APT Malware Infection Detection Using URL Correlation Analysis
