import re
def parse_log_line(line):
    # Example log line format:
    # Dec 20 11:31:24 DESKTOP-0KC9F2L kernel: [11974.490683] INPUT: IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=127.0.0.1 DST=127.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=62923 DF PROTO=TCP SPT=49104 DPT=5000 WINDOW=65495 RES=0x00 SYN URGP=0
    pattern = re.compile(r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>\S+) kernel: \[\d+\.\d+\] (?P<chain>\w+): IN=(?P<in>\S*) OUT=(?P<out>\S*) MAC=(?P<mac>\S*) SRC=(?P<src>\S*) DST=(?P<dst>\S*) LEN=(?P<len>\d+) TOS=(?P<tos>\S*) PREC=(?P<prec>\S*) TTL=(?P<ttl>\d+) ID=(?P<id>\d+) DF PROTO=(?P<proto>\S*) SPT=(?P<spt>\d+) DPT=(?P<dpt>\d+) WINDOW=(?P<window>\d+) RES=(?P<res>\S*) SYN URGP=(?P<urgp>\d+)' )
    match = pattern.match(line)
    if match:
        return match.groupdict()
    return {}
print(parse_log_line("2024-12-22T23:24:59.573504-05:00 kali kernel: OUTPUT LOG: IN= OUT=eth0 SRC=10.0.2.128 DST=10.0.2.1 LEN=216 TOS=0x10 PREC=0x00 TTL=64 ID=34686 DF PROTO=TCP SPT=22 DPT=55616 WINDOW=697 RES=0x00 ACK PSH URGP=0"))