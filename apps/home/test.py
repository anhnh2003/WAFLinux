import re

def validate_iptables_command(command):
    # Define a strict regular expression to match valid iptables commands
    iptables_pattern = re.compile(
        r"^sudo\s+iptables\s+"
        r"(-[A-Z]\s+)?"
        r"(-[a-zA-Z0-9-]+(\s+[a-zA-Z0-9.:/-]+)*)\s*"
        r"(-j\s+[A-Z]+)?$"
    )

    # Check if the command matches the pattern
    if not iptables_pattern.match(command):
        return False

    # Ensure the command does not contain any potentially harmful characters or sequences
    forbidden_patterns = [
        r";",  # Command chaining
        r"&",  # Background execution
        r"\|",  # Pipe
        r"`",  # Command substitution
        r"\$",  # Variable substitution
        r">",  # Output redirection
        r"<",  # Input redirection
    ]

    for pattern in forbidden_patterns:
        if re.search(pattern, command):
            return False

    # Validate command structure further
    allowed_keywords = [
        "INPUT", "OUTPUT", "FORWARD",
        "ACCEPT", "DROP", "REJECT",
        "--icmp-type", "-A", "-D", "-I", "-R", "-L", "-F", "-P",
        "-s", "-d", "-p", "-m", "-j", "--dport", "--sport",
        "tcp", "udp", "icmp", "all"
    ]
    
    command_parts = command.split()
    for part in command_parts:
        # Skip options with values (e.g., IPs or ports) as they're dynamic
        if part.startswith("-") or part.startswith("--"):
            if part not in allowed_keywords and not re.match(r"^[0-9.:-]+$", part):
                return False

    return True

# Test the function
print(validate_iptables_command("sudo iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT"))  # True