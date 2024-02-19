'''
    automatically generate the suitable format for following log parsing

    generate regex:
        domain: \b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b
        ipv4: \b(?:\d{1,3}\.){3}\d{1,3}\b
        ipv6: \b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b
        request parameter: \?[^\s]+
'''
import spacy
import nltk
import flair

# total_entities = ["<Month>", "<Date>", "Time", ""]

# # dnsmasq
# dns_str = "Jan 14 08:16:58 dnsmasq[14460]: using nameserver 127.0.0.1#53 \
#             for domain 228.131.168.192.in-addr.arpa"
# dns_log_format = "<Month> <Date> <Time> <Component>\[<PID>\]: <Content>"

# # windows 7 logs CBS
# win_str = "2016-09-28 04:30:31, Info                  CBS    SQM: Failed to start upload with file pattern: \
#         C:\Windows\servicing\sqm\*_std.sqm,flags: 0x2 [HRESULT = 0x80004005 - E_FAIL]"
# win_log_format = "<Date> <Time> <Level> <Component>\[<PID>\]: <Content>"


# # linux message
# linux_str = "Aug 29 07:22:25 combo sshd(pam_unix)[796]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220.82.197.48  user=root"
# linux_log_format = "<>"


# the matching format for unstructured logs
format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Date> <Time> <Component>(\[<PID>\])?: <Content>",
            # match the domain, ipv4 and ipv6
            "regex": [r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"],
            "st":0.7,
            "depth":4,
            # filter for domain name match with general domain extension
            "filter": 1,
            "key":0,
        },
    },
    "Apache": {
        "org-access": {
            "log_format": "<IP> -- \[<Time>\] <Context> <Status_Code> <Response_Size> <Referer> <User-Agent>",
            # match the parameter part
            "regex": [r"\?[^\s]+"],
            "st": 0.8,
            "depth": 4,
            "filter":0,
            "key":0,
        },
        "audit": {
            "log_format": "<Type> <Time>: <PID> <UID> <AUID> <SES> <Context>",
            "regex": [r"\/(?:[\w-]+\/)+[\w-]+"],
            "st":0.8,
            "depth": 6,
            "filter":1,
            "key":1,
        },
        "auth": {
            "log_format": "<Date> <Time> <Component> <Level>\[<PID>\]: <Context>",
            "regex": [],
            "st": 0.6,
            "depth": 4,
            "filter": 0,
            "key":0,
        },
    }
}