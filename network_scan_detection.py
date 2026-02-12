#!/usr/bin/env python3

import re

test_file = "/var/log/iptables.log.1"

#compiled regex patterns for syslog file 

SRC = re.compile(r'\bSRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)')
DST = re.compile(r'\bDST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)')
PROTO = re.compile(r'\bPROTO=(?P<proto>TCP|UCP|ICMP)')
SPT = re.compile(r'\bSPT=(?P<src_port>\d+)')
DPT = re.compile(r'\bDPT=(?P<dst_port>\d+)')

patterns = [SRC, DST, PROTO, SPT, DPT]


with open(test_file, 'r') as f:
    for line in f:
        extracted = {}

        for pattern in patterns:
            key = pattern.search(line)
            if key:
                extracted.update(key.groupdict())

        if extracted:
            print("SCAN DETECTED: ")
            print(extracted)

