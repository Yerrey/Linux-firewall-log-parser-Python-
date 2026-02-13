#!/usr/bin/env python3

import re

#test_file is a small snippet of the actual log. 
test_file = "/var/log/iptables.log.1"

#compiled regex patterns for syslog file 

SRC = re.compile(r'\bSRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)')
DST = re.compile(r'\bDST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)')
PROTO = re.compile(r'\bPROTO=(?P<proto>TCP|UCP|ICMP)')
SPT = re.compile(r'\bSPT=(?P<src_port>\d+)')
DPT = re.compile(r'\bDPT=(?P<dst_port>\d+)')

#patterns to loop over 
patterns = [SRC, DST, PROTO, SPT, DPT]


with open(test_file, 'r') as f:
    for line in f:
        extracted = {}

        for pattern in patterns:
            key_field = pattern.search(line)
            if key_field:
                extracted.update(key_field.groupdict())

            FLAGS = {
                "SYN": bool(re.search(r'\bSYN\b', line)),
                "FIN": bool(re.search(r'\bFIN\b', line)),
                "ACK": bool(re.search(r'\bACK\b', line)),
                "PSH": bool(re.search(r'\bPSH\b', line)),
                "URG": bool(re.search(r'\bURG\b', line)),
                "RST": bool(re.search(r'\bRST\b', line)),
            }

        if extracted:
            if FLAGS["SYN"] and not FLAGS["ACK"]:
                scan = "SYN SCAN"
                print(f"{scan} Detected: ")
                print(extracted)
            elif FLAGS["FIN"] and FLAGS["PSH"] and FLAGS["URG"]:
                scan = "XMAS SCAN"
                print(f"{scan} Detected: ")
                print(extracted)
            elif FLAGS["FIN"] and not FLAGS["SYN"]:
                scan = "FIN SCAN" 
                print(f"{scan} Detected: ")
                print(extracted)
            elif FLAGS["ACK"] and not FLAGS["SYN"]:
                scan = "ACK SCAN"
                print(f"{scan} Detected: ")
                print(extracted)
            elif not any(FLAGS.values()):
                scan = "NULL SCAN"
                print(f"{scan} Detected: ")
            else:
                scan = "UNKNOWN SCAN"
                print(f"{scan} Detected: ")
                print(extracted)
