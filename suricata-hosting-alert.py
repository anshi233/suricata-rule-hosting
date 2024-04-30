#!/usr/bin/python3

import requests

def generate_suricata_rules_mining(url):
    # Download the file content from the GitHub URL
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to download the file")
        return
    
    # Extract lines as individual TLDs
    tlds = response.text.splitlines()
    
    # Generate Suricata rules
    rules = []
    rule_id = 1000000
    for tld in tlds:
        if tld:
            rule = f"alert dns any any -> any any (msg:\"[Coin Mining] DNS lookup for .{tld}\"; dns.query; content:\".{tld}\"; nocase; sid:{rule_id}; rev:1;)"
            rules.append(rule)
            rule_id += 1
    
    return rules

def generate_suricata_rules_proxy(url):
    # Download the file content from the GitHub URL
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to download the file")
        return
    
    # Extract lines as individual TLDs
    tlds = response.text.splitlines()
    
    # Generate Suricata rules
    rules = []
    rule_id = 1000000
    for tld in tlds:
        if tld:
            rule = f"alert dns any any -> any any (msg:\"[Public Proxy] DNS lookup for .{tld}\"; dns.query; content:\".{tld}\"; nocase; sid:{rule_id}; rev:1;)"
            rules.append(rule)
            rule_id += 1
    
    return rules

# URL to the TLD list on GitHub
url = "https://raw.githubusercontent.com/ilmoi/mining-pools-aggregator/master/lists/tlds.txt"
rules = generate_suricata_rules_mining(url)

# Output the rules or write to a file
for rule in rules:
    print(rule)

# URL to the TLD list on GitHub
url = "https://raw.githubusercontent.com/anshi233/suricata-rule-hosting/master/mining/tld.txt"
rules = generate_suricata_rules_mining(url)

# Output the rules or write to a file
for rule in rules:
    print(rule)

# URL to the TLD list on GitHub
url = "https://raw.githubusercontent.com/anshi233/suricata-rule-hosting/master/public-proxy/tld.txt"
rules = generate_suricata_rules_proxy(url)

# Output the rules or write to a file
for rule in rules:
    print(rule)
