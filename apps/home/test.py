import re

def parse_log_line(line):
    # Define the regex pattern
    pattern = re.compile(
        r'(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+kernel:\s+(?P<chain>[A-Z]+)\s+LOG:\s+'
        r'IN=(?P<in_interface>\S*)\s+OUT=(?P<out_interface>\S*)\s+SRC=(?P<src_ip>\S+)\s+'
        r'DST=(?P<dst_ip>\S+)\s+LEN=(?P<length>\d+)\s+TOS=(?P<tos>\S+)\s+PREC=(?P<prec>\S+)\s+'
        r'TTL=(?P<ttl>\d+)\s+ID=(?P<id>\d+)\s+(?P<flags>\S+)\s+PROTO=(?P<protocol>\S+)\s+'
        r'SPT=(?P<src_port>\d+)\s+DPT=(?P<dst_port>\d+)\s+WINDOW=(?P<window>\d+)\s+'
        r'RES=(?P<res>\S+)\s+(?P<detail>.+)?'
    )

    # Match the line using the pattern
    match = pattern.match(line)

    # If the pattern matches, return a dictionary of parsed fields
    if match:
        return match.groupdict()
    return {}

# Example usage
log_line = "2024-12-22T23:24:59.573504-05:00 kali kernel: OUTPUT LOG: IN= OUT=eth0 SRC=10.0.2.128 DST=10.0.2.1 LEN=216 TOS=0x10 PREC=0x00 TTL=64 ID=34686 DF PROTO=TCP SPT=22 DPT=55616 WINDOW=697 RES=0x00 ACK PSH URGP=0"
parsed = parse_log_line(log_line)
print(parsed)
