# pyports
A simple Python port scanner with Scapy

The following packages must be installed:
scapy
argparse
tabulate

Tested on Python 2.7.9

Usage of pyports:

python pyports.py <HOSTS> <PORTS> <Options>

<HOSTS> can be a single IP, IP Range ("192.168.101.10-192.168.101.50") or CIDR-notated subnet ("192.168.101.0/24")
<PORTS> must be a comma-separated list of ports to scan ("22,80,443")

Additional switches are as follows:
--h, --help - Shows help message
-t Include a basic traceroute for each IP. As it is a Scapy traceroute, it will repeat the final host until the end of the set ttl
-s Perform a syn stealth scan
