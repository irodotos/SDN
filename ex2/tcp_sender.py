import socket
import sys
import time

assert(len(sys.argv) == 3)

TCP_IP = sys.argv[1]
TCP_PORT = int(sys.argv[2])
MESSAGE = "HY436"

print "TCP target IP:", TCP_IP
print "TCP target port:", TCP_PORT
print "message:", MESSAGE

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((TCP_IP, TCP_PORT))

while True:
    sock.send(MESSAGE)
    time.sleep(2)

sock.close()
