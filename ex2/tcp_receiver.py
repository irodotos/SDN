#!/usr/bin/env python

import socket
import sys

assert(len(sys.argv) == 4)

TCP_IP = sys.argv[1]
TCP_PORT = int(sys.argv[2])
BUFFER_SIZE = int(sys.argv[3])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((TCP_IP, TCP_PORT))
sock.listen(1)

conn, addr = sock.accept()
print 'Connection established with ', addr[0]

while True:
    data = conn.recv(BUFFER_SIZE)

    if data:
        print "Received %s from host %s on port %s over TCP." %(data,addr[0],addr[1])
    
conn.close()
