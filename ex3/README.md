### How do I get set up? ###

* copy your folder files to the P4 tutorial VM
* cd <your_exercise_folder>
* ```make run```
* test with mininet
* ```make stop```
* ```make clean```

### Useful commands ###

* Setup xterm on mininet host: xterm <host_name> # note that the SSH connection should enable X11 forwarding for this to work, e.g., with the -X option
* Monitor traffic without the LLDP, ARP and ONOS packets: tcpdump -ni <IFACE> not ether proto 0x88cc and not ether proto 0x8942 and not arp
* Monitor only ICMP traffic: tcpdump -ni <IFACE> icmp
