import socket
import sys
import time

assert(len(sys.argv) == 3)

UDP_IP = sys.argv[1]
UDP_PORT = int(sys.argv[2])
MESSAGE = "HY436"

print "UDP target IP:", UDP_IP
print "UDP target port:", UDP_PORT
print "message:", MESSAGE

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
    time.sleep(2)
