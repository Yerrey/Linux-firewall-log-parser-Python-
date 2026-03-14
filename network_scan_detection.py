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
offset_file = os.getenv("OFFSET_FILE")



 

SRC = re.compile(r'\bSRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)')
DST = re.compile(r'\bDST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)')
PROTO = re.compile(r'\bPROTO=(?P<proto>TCP|UDP|ICMP)')
SPT = re.compile(r'\bSPT=(?P<src_port>\d+)')
DPT = re.compile(r'\bDPT=(?P<dst_port>\d+)')


patterns = [SRC, DST, PROTO, SPT, DPT]

def load_offset(offset_file):
    if os.path.exists(offset_file):
        with open(offset_file, 'r') as f:
            content = f.read().strip()
            if not content:
                return 0, None
            data = json.loads(content)
            return data.get("offset", 0), data.get("inode", None)
    return 0, None

def save_offset(offset_file, offset, inode):
    with open(offset_file, "w") as f:
        json.dump({"offset": offset, "inode": inode}, f)


def log_scan(scan_type, details, output_file):

    with open(output_file, "a") as out:
        scan_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "scan_type": scan_type,
            "details": details
        }
        out.write(json.dumps(scan_data, indent = 4) + '\n')



saved_offset, saved_inode = load_offset(offset_file)
current_inode = os.stat(file).st_ino

if saved_inode is not None and current_inode != saved_inode:
    saved_offset = 0

with open(file, 'r') as f:
    f.seek(saved_offset)

    
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

            scan = None
            
            if FLAGS["SYN"] and not FLAGS["ACK"]:
                scan = "SYN SCAN"
            elif FLAGS["FIN"] and FLAGS["PSH"] and FLAGS["URG"]:
                scan = "XMAS SCAN"
            elif FLAGS["FIN"] and not FLAGS["SYN"]:
                scan = "FIN SCAN"
            elif FLAGS["ACK"] and not FLAGS["SYN"]:
                scan = "ACK SCAN"
            elif not any(FLAGS.values()):
                scan = "NULL SCAN"

            if scan:
                log_scan(scan,extracted,output_file)

    save_offset(offset_file, f.tell(), current_inode)
                
                        
                
