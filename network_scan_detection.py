#!/usr/bin/env python3

import re
import json 
import datetime 
import os 
from dotenv import load_dotenv

load_dotenv()



#file paths 
file = "/var/log/iptables.log"
output_file = os.getenv("OUTPUT_FILE")
time = datetime.datetime.now().isoformat()


 

SRC = re.compile(r'\bSRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)')
DST = re.compile(r'\bDST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)')
PROTO = re.compile(r'\bPROTO=(?P<proto>TCP|UDP|ICMP)')
SPT = re.compile(r'\bSPT=(?P<src_port>\d+)')
DPT = re.compile(r'\bDPT=(?P<dst_port>\d+)')


patterns = [SRC, DST, PROTO, SPT, DPT]



def log_scan(scan_type, details, output_file):

    with open(output_file, "a") as out:
        scan_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "scan_type": scan_type,
            "details": details
        }
        out.write(json.dumps(scan_data) + '\n')


with open(file, 'r') as f:
    for line in f:
        if "NETWORK SCAN DETECTED" not in line:
            continue
        
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
                log_scan(scan, extracted, output_file)
                print()
                
            elif FLAGS["FIN"] and FLAGS["PSH"] and FLAGS["URG"]:
                scan = "XMAS SCAN"
                log_scan(scan, extracted, output_file)
                print()
                
            elif FLAGS["FIN"] and not FLAGS["SYN"]:
                scan = "FIN SCAN"
                log_scan(scan, extracted, output_file)
                print()
                
            elif FLAGS["ACK"] and not FLAGS["SYN"]:
                scan = "ACK SCAN"
                log_scan(scan, extracted, output_file)
                print()
                
            elif not any(FLAGS.values()):
                scan = "NULL SCAN"
                log_scan(scan , extracted, output_file)
                print()
            else:
                continue
                
