import socket
import sys

assert(len(sys.argv) == 4)

UDP_IP = sys.argv[1]
UDP_PORT = int(sys.argv[2])
BUFFER_SIZE = int(sys.argv[3])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(int(BUFFER_SIZE)) 
    if data:
        print "Received %s from host %s on port %s over UDP." %(data,addr[0],addr[1])
