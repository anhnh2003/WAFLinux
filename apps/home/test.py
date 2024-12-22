import re
def parse_iptables_output(output):
    #parse the output into a list of lists, where each inner list represents a row of the iptables output
    #the inner lists must have the following format: [target, prot, opt, source, destination, s_port, d_port, detail], if the corresponding field is not present in the output, the value should be an empty string
    #example output: ACCEPT all -- anywhere anywhere tcp dpt:https ctstate NEW
    #the correct format should be: ['ACCEPT', 'tcp', '-- 'anywhere', 'anywhere', '', 'https', 'ctstate NEW']
    table_data = []
    lines = output.split('\n')
    for line in lines:
        if line.startswith('Chain'):
            continue
        if line.startswith('target'):
            continue
        #if line.startswith('ACCEPT') or line.startswith('DROP') or line.startswith('REJECT') or line.startswith('RETURN'):
        parts = line.split()
        print(len(parts))
        target = parts[0]
        prot = parts[1]
        opt = parts[2]
        source = parts[3]
        destination = parts[4]
        
        s_port_match = re.search(r'spt:(\S+)', line)
        s_port = s_port_match.group(1) if s_port_match else 'any'
        
        d_port_match = re.search(r'dpt:(\S+)', line)
        d_port = d_port_match.group(1) if d_port_match else 'any'
        
        # Remove the known fields from the line to get the detail
        detail = line
        for field in [target, prot, opt, source, destination, f'spt:{s_port}', f'dpt:{d_port}']:
            detail = detail.replace(field, '', 1).strip()
        
        table_data.append([target, prot, opt, source, destination, s_port, d_port, detail])
    return table_data
#parse a sample iptables output
output = '''Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere             tcp dpt:https ctstate NEW
ufw-before-logging-input  all  --  anywhere             anywhere
ufw-before-input  all  --  anywhere             anywhere
ufw-after-input  all  --  anywhere             anywhere
ufw-after-logging-input  all  --  anywhere             anywhere
ufw-reject-input  all  --  anywhere             anywhere
ufw-track-input  all  --  anywhere             anywhere'''
print(parse_iptables_output(output))