import re
from collections import Counter
def parse_log_line(line):
    # Define the regex pattern
    pattern = re.compile(
        r'(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+kernel:\s+(?P<chain>[A-Z]+)\s+LOG:\s+'
        r'IN=(?P<in_interface>\S*)\s+OUT=(?P<out_interface>\S*)\s+'
        r'(?:MAC=(?P<mac>[A-Fa-f0-9: ]+)\s+)?'
        r'SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+)\s+LEN=(?P<length>\d+)\s+'
        r'TOS=(?P<tos>\S+)\s+PREC=(?P<prec>\S+)\s+'
        r'TTL=(?P<ttl>\d+)\s+ID=(?P<id>\d+)\s+'
        r'(?:DF\s+)?PROTO=(?P<protocol>\S+)\s+'
        r'(?:SPT=(?P<src_port>\d+)\s+DPT=(?P<dst_port>\d+)\s+)?'
        r'(?:TYPE=(?P<type>\d+)\s+CODE=(?P<code>\d+)\s+ID=(?P<icmp_id>\d+)\s+SEQ=(?P<icmp_seq>\d+)\s+)?'
        r'(?:WINDOW=(?P<window>\d+)\s+RES=(?P<res>\S+)\s+)?'
        r'(?P<detail>.+)?'
    )

    # Match the line using the pattern
    match = pattern.match(line)

    # If the pattern matches, return a dictionary of parsed fields
    if match:
        return match.groupdict()
    return {}
import json
def data_visualization():
    file = '''
2024-12-24T10:48:07.096240-05:00 kali kernel: OUTPUT LOG: IN= OUT=eth0 SRC=10.0.2.128 DST=10.0.2.1 LEN=4184 TOS=0x10 PREC=0x00 TTL=64 ID=22697 DF PROTO=TCP SPT=22 DPT=63996 WINDOW=249 RES=0x00 ACK PSH URGP=0
2024-12-24T10:48:07.100244-05:00 kali kernel: INPUT LOG: IN=eth0 OUT= MAC=00:0c:29:ac:6b:50:00:50:56:c0:00:08:08:00 SRC=10.0.2.1 DST=10.0.2.128 LEN=52 TOS=0x10 PREC=0x00 TTL=63 ID=4930 DF PROTO=TCP SPT=63996 DPT=22 WINDOW=4644 RES=0x00 ACK URGP=0
2024-12-24T10:48:07.100246-05:00 kali kernel: INPUT LOG: IN=eth0 OUT= MAC=00:0c:29:ac:6b:50:00:50:56:c0:00:08:08:00 SRC=10.0.2.1 DST=10.0.2.128 LEN=52 TOS=0x10 PREC=0x00 TTL=63 ID=4931 DF PROTO=TCP SPT=63996 DPT=22 WINDOW=4644 RES=0x00 ACK URGP=0
2024-12-24T10:48:07.100247-05:00 kali kernel: INPUT LOG: IN=eth0 OUT= MAC=00:0c:29:ac:6b:50:00:50:56:c0:00:08:08:00 SRC=10.0.2.1 DST=10.0.2.128 LEN=52 TOS=0x10 PREC=0x00 TTL=63 ID=4932 DF PROTO=TCP SPT=63996 DPT=22 WINDOW=4646 RES=0x00 ACK URGP=0
2024-12-24T10:48:07.100250-05:00 kali kernel: INPUT LOG: IN=eth0 OUT= MAC=00:0c:29:ac:6b:50:00:50:56:c0:00:08:08:00 SRC=10.0.2.1 DST=10.0.2.128 LEN=52 TOS=0x10 PREC=0x00 TTL=63 ID=4933 DF PROTO=TCP SPT=63996 DPT=22 WINDOW=4646 RES=0x00 ACK URGP=0
2024-12-24T10:48:07.100223-05:00 kali kernel: OUTPUT LOG: IN= OUT=eth0 SRC=10.0.2.128 DST=10.0.2.1 LEN=4184 TOS=0x10 PREC=0x00 TTL=64 ID=22700 DF PROTO=TCP SPT=22 DPT=63996 WINDOW=249 RES=0x00 ACK PSH URGP=0
2024-12-24T10:48:07.100241-05:00 kali kernel: OUTPUT LOG: IN= OUT=eth0 SRC=10.0.2.128 DST=10.0.2.1 LEN=4184 TOS=0x10 PREC=0x00 TTL=64 ID=22703 DF PROTO=TCP SPT=22 DPT=63996 WINDOW=249 RES=0x00 ACK PSH URGP=0
'''
    # Split the multiline string into lines
    log_entries = []
    for line in file.strip().splitlines():
        log_entries.append(parse_log_line(line))
    
    if not log_entries:
        return "No log entries to visualize."

    # Fields to visualize
    fields = ["src_ip", "dst_ip", "protocol", "in_interface", "out_interface", "detail"]
    
    # Aggregated data for each field
    aggregated_data = {}
    for field in fields:
        values = [entry[field] for entry in log_entries if field in entry and entry[field]]
        if values:
            counter = Counter(values)
            aggregated_data[field] = [[key, value] for key, value in counter.items()]

    # Send data to the template
    aggregated_data = json.dumps(aggregated_data, indent=4)
    return aggregated_data

# Test the function
print('hello',data_visualization())
