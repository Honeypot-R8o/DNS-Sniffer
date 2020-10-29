from threading import Thread
from scapy.all import *
from netaddr import *
import datetime
from time import sleep
import netifaces as ni
import optparse
import smtplib
import sys

dnslist=[]
iplist=[]

dhcpname={}

def startscreen():
	print('\033c')
	print("****************************************")
	print("* DNS-Sniffer  V.1.1 by Reto Schaedler *")
	print("****************************************")
	print()


def packetSniffer(pkt):
	global dnslist
	global iplist
	if pkt.haslayer(DNSQR):
		dnslist.append(str(pkt[DNS].qd.qname)[2:-2])
		if IPv6 in pkt:
			iplist.append(str(pkt[IPv6].dst))
		else:
			iplist.append(str(pkt[IP].dst))


def dnsSniffer():
	global intf
	ni.ifaddresses(intf)
	#localIP = ni.ifaddresses(intf)[ni.AF_INET][0]['addr']
	#filterstr="udp and src port 53 and (host not " + localIP + ")"
	filterstr="udp and src port 53"
	sniff(filter=filterstr, iface=intf, store=0, prn=packetSniffer)


def dnsChecker():
	global dnslist
	global iplist
	global dhcpname
	while True:
		if(len(dnslist)):
			try:
				#print("****************************************")
				print(dnslist[0])
				print(iplist[0], end='')
				if iplist[0] in dhcpname:
					clientname=dhcpname[iplist[0]]					
				else:
					clientname="Unknown-Host-Name"
				print(" " + clientname)
				print ("Time:",datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
				print("****************************************")
				sys.stdout.flush()
				del(dnslist[0])
				del(iplist[0])
			except (KeyboardInterrupt, SystemExit):
				raise
			except:
				del(dnslist[0])
				del(iplist[0])

		else:
				sleep(0.1)


def get_option(dhcp_options, key):

	must_decode = ['hostname', 'domain', 'vendor_class_id']
	try:
		for i in dhcp_options:
			if i[0] == key:
				# If DHCP Server Returned multiple name servers 
				# return all as comma seperated string.
				if key == 'name_server' and len(i) > 2:
					return ",".join(i[1:])
				# domain and hostname are binary strings,
				# decode to unicode string before returning
				elif key in must_decode:
					return i[1].decode()
				else: 
					return i[1]        
	except:
		pass


def handle_dhcp_packet(packet):
	global dhcpname
	# Match DHCP request
	if DHCP in packet and packet[DHCP].options[0][1] == 3:
		requested_addr = get_option(packet[DHCP].options, 'requested_addr')
		hostname = get_option(packet[DHCP].options, 'hostname')
		if packet[IP].src == "0.0.0.0":		
			dhcpname[requested_addr]=hostname
		else:
			dhcpname[str(packet[IP].src)]=hostname
	return

def dhcpListener():
	global intf
	sniff(filter="udp and (port 67 or 68)", iface=intf,prn=handle_dhcp_packet)


if __name__ == '__main__':

	parser = optparse.OptionParser()
	parser.add_option('-i', '--interface',
	    action="store", dest="interface",
	    help="query string", default="eth0")
	options, args = parser.parse_args()

	intf=options.interface

	startscreen()


	th = Thread(target=dnsSniffer)
	th.start()

	th1 = Thread(target=dnsChecker)
	th1.start()
	
	th2 = Thread(target=dhcpListener)
	th2.start()
