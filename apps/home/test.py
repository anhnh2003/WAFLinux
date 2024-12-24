import re

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

# Example usage
log_line = "2024-12-22T23:24:59.573504-05:00 kali kernel: INPUT LOG: IN= OUT=eth0 SRC=10.0.2.128 DST=10.0.2.1 LEN=216 TOS=0x10 PREC=0x00 TTL=64 ID=34686 DF PROTO=TCP SPT=22 DPT=55616 WINDOW=697 RES=0x00 ACK PSH URGP=0"
log_line2 = "2024-12-23T09:52:03.333880-05:00 kali kernel: INPUT LOG: IN=eth0 OUT= MAC=00:0c:29:ac:6b:50:00:50:56:f9:45:95:08:00 SRC=142.250.198.142 DST=10.0.2.128 LEN=84 TOS=0x00 PREC=0x00 TTL=128 ID=42035 PROTO=ICMP TYPE=0 CODE=0 ID=17611 SEQ=2"
log_line3 = "2024-12-23T09:52:07.302870-05:00 kali kernel: OUTPUT LOG: IN= OUT=eth0 SRC=10.0.2.128 DST=142.250.198.142 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=60349 DF PROTO=ICMP TYPE=8 CODE=0 ID=17611 SEQ=6"
parsed = parse_log_line(log_line)
print(parsed)
parsed2 = parse_log_line(log_line2)
print(parsed2)
parsed3 = parse_log_line(log_line3)
print(parsed3)

