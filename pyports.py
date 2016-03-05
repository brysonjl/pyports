#Port Scanner
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
from tabulate import tabulate
from netaddr import *

#Handle script arguments
parser = argparse.ArgumentParser()
parser.add_argument("dest", help="Add the IP address, IP range (i.e 192.168.1.1-192.168.2.25), or CIDR-notation subnet (i.e. 192.168.1.0/23)")
parser.add_argument("ports", help="Add a comma-separated list of ports. e.g.(80,123,443,500)")
parser.add_argument("-t", default=False, dest="traceroute", action='store_true', help="Include a traceroute for each IP. As it is a Scapy traceroute, will repeat the final host.")
parser.add_argument("-s", default=False, dest="stealth", action="store_true", help="Perform a syn stealth scan.")
args = parser.parse_args()
#Handle IP Ranges
if "-" in args.dest:
	ip_range = args.dest.split('-')
	ips = IPRange(ip_range[0],ip_range[1])
#Handle single IPs, or CIDR subnets
else:
	ips = IPSet([str(args.dest)])
ports = args.ports.split(',')

def main():
	#If the stealth scan argument has been specified, perform a stealth scan using scapy
	if args.stealth==1:
		try:
			for ip in ips:
				print "Stealth Scanning " + str(ip)
				dst_ip = str(ip)
				p_status=[]
				for port in ports:
					#Scan the port with Scapy
					#Code to scan a port with Scapy adapted from tutorial at http://resources.infosecinstitute.com/port-scanning-using-scapy/
					src_port=RandShort()
					dst_port = int(port)
					stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='S'),timeout=10,verbose=False)
					if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
						 p_status.append([dst_port, "Filtered"])
					elif(stealth_scan_resp.haslayer(TCP)):
						if(stealth_scan_resp.getlayer(TCP).flags==0x12):
							send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10,verbose=False)
							p_status.append([dst_port, "Open"])
						elif (stealth_scan_resp.getlayer(TCP).flags==0x14):
							p_status.append([dst_port, "Closed"])
						elif (stealth_scan_resp.haslayer(ICMP)):
							if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
								p_status.append([dst_port, "Filtered"])
				#Print out results in table
				print "--------------------------------------------"
				print dst_ip
				print tabulate(p_status,["Port","Status"], tablefmt="grid")
				print "--------------------------------------------"
				if args.traceroute==1:
					result, unans = traceroute([dst_ip],maxttl=16)
		except:
			print "Uh Oh. Something went wrong. Maybe try --help to see proper syntax?"
	#Otherwise perform a normal scan	
	else:		
		try:
			for ip in ips:
				print "Scanning " + str(ip)
				dst_ip = str(ip)
				p_status=[]
				for port in ports:
					#Scan the port with Scapy
					src_port=RandShort()
					dst_port = int(port)
					tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='S'),timeout=10,verbose=False)
					if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
						 p_status.append([dst_port, "Closed"])
					elif(tcp_connect_scan_resp.haslayer(TCP)):
						if(tcp_connect_scan_resp.getlayer(TCP).flags==0x12):
							send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10,verbose=False)
							p_status.append([dst_port, "Open"])
						elif (tcp_connect_scan_resp.getlayer(TCP).flags==0x14):
							p_status.append([dst_port, "Closed"])
				#Print out results in a table
				print "--------------------------------------------"
				print dst_ip
				print tabulate(p_status,["Port","Status"], tablefmt="grid")
				print "--------------------------------------------"
				if args.traceroute==1:
					result, unans = traceroute([dst_ip],maxttl=16)
		except:
			print "Uh Oh. Something went wrong. Maybe try --help to see proper syntax?"
main()
