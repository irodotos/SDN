from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet , ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random
import json # addition to read configuration from file


class SimpleLoadBalancer(object):


    # initialize SimpleLoadBalancer class instance
    def __init__(self, lb_mac = None, service_ip = None,
                 server_ips = [], user_ip_to_group = {}, server_ip_to_group = {}):

        # add the necessary openflow listeners
        core.openflow.addListeners(self)

        self.service_ip = service_ip
        print("service ip = " , service_ip)
        self.lb_mac = lb_mac
        print("lb mac = " , lb_mac)
        self.server_ips = server_ips
        print("server ips = " , server_ips)
        self.user_ip_to_group = user_ip_to_group
        print("user ip to group = " , user_ip_to_group)
        self.server_ip_to_group = server_ip_to_group
        print("server ip to group = " , server_ip_to_group)

        print("INIT JUST RUN")
        # set class parameters
        self.servers_ip_mac = {}
        self.clients_ip_mac = {}
        # write your code here!!!

        pass


    # respond to switch connection up event
    def _handle_ConnectionUp(self, event):
        print("HANDLE CONNECTION JUST RUN")
        self.connection = event.connection
        # write your code here!!!
        for server_ip in self.server_ips:
            # print("server ip = " , server_ip)
            # print("typeof server ip = " , type(server_ip))
            self.send_proxied_arp_request(self.connection , server_ip)
        pass


    # update the load balancing choice for a certain client
    def update_lb_mapping(self, client_ip):
        # write your code here!!!
        pass


    # send ARP reply "proxied" by the controller (on behalf of another machine in network)
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        print("SEND ARP REPLAY JUST RUN")
        arp_reply          = arp()
        arp_reply.opcode   = arp.REPLY
        arp_reply.hwsrc    = requested_mac
        arp_reply.hwdst    = packet.payload.hwsrc
        arp_reply.protosrc = packet.payload.protodst
        arp_reply.protodst = packet.payload.protosrc

        ether         = ethernet()
        ether.type    = ethernet.ARP_TYPE
        ether.src     = requested_mac
        ether.dst     = packet.src
        ether.payload = arp_reply

        msg      = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = outport))

        connection.send(msg)


    # send ARP request "proxied" by the controller (so that the controller learns about another machine in network)
    def send_proxied_arp_request(self, connection, ip):
        print("SEND ARP REQUEST JUST RUN")
        arp_request          = arp()
        arp_request.opcode   = arp.REQUEST
        arp_request.hwsrc    = self.lb_mac
        arp_request.hwdst    = ETHER_BROADCAST
        arp_request.protosrc = self.service_ip
        arp_request.protodst = ip

        ether         = ethernet()
        ether.type    = ethernet.ARP_TYPE
        ether.src     = self.lb_mac
        ether.dst     = ETHER_BROADCAST
        ether.payload = arp_request

        msg      = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))

        connection.send(msg)


    # install flow rule from a certain client to a certain server
    def install_flow_rule_client_to_server(self, connection,inport, outport, client_ip, server_ip, server_mac , buffer_id=of.NO_BUFFER):
    
        myMatch = of.ofp_match()
        myMatch.nw_src = client_ip
        myMatch.nw_dst = self.service_ip
        myMatch.nw_proto = 1
        myMatch.dl_type = 0x800
        myMatch.dl_src = self.clients_ip_mac[client_ip][0]
        myMatch.dl_dst = self.servers_ip_mac[server_ip][0]
        myMatch.in_port = inport

        actions = []
        actions.append(of.ofp_action_nw_addr.set_src(client_ip))
        actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        print("actions srver ip = " , server_ip)
        actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        actions.append(of.ofp_action_output(port = outport))

        msg = of.ofp_flow_mod()
        # msg.command = of.OFPFC_ADD
        msg.idle_timeout = 10
        msg.match = myMatch
        msg.buffer_id = buffer_id
        msg.actions = actions

        connection.send(msg)


    # install flow rule from a certain server to a certain client
    def install_flow_rule_server_to_client(self, connection,inport, outport, server_ip, client_ip, client_mac, buffer_id=of.NO_BUFFER):

        myMatch = of.ofp_match()
        myMatch.nw_src = server_ip
        myMatch.nw_dst = client_ip
        # myMatch.dl_type = 0x800
        # myMatch.dl_src = self.servers_ip_mac[server_ip][0]
        myMatch.in_port = inport

        actions = []
        actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
        actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
        actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
        actions.append(of.ofp_action_output(port = outport))

        msg = of.ofp_flow_mod()
        # msg.command = of.OFPFC_ADD
        msg.idle_timeout = 10
        msg.match = myMatch
        msg.buffer_id = buffer_id
        msg.actions = actions

        connection.send(msg)

    def random_fun(self , client_color):
        rand = random.randint(0,1)
        if rand == 0:
            if client_color == "red":
                server_ip = self.server_ips[0]
            else:
                server_ip = self.server_ips[2]
        elif rand == 1:
            if client_color == "red":
                server_ip = self.server_ips[1]
            else:
                server_ip = self.server_ips[3]
        else:
            print("RANDOM NUMBER IS NOT 0 OR 1")
            return
        return server_ip

    # main packet-in handling routine
    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
        if packet.type == packet.ARP_TYPE:
            if packet.payload.opcode == 2:    # REPLY
                print("RECIEVED ARP REPLAY")
                arp = packet.payload
                self.servers_ip_mac[arp.protosrc] = [ arp.hwsrc , inport ]
                print('dictionary = ' , self.servers_ip_mac )
            elif packet.payload.opcode == 1: # REQUEST
                print("RECIEVED ARP REQUEST")
                arp_req = packet.payload
                print("ip src = " , arp_req.protosrc)
                print("ip dest = " ,arp_req.protodst)
                print("mac src = " ,arp_req.hwsrc)
                print("mac dst = ",arp_req.hwdst)
                if arp_req.protosrc in self.server_ips:  #IF IT SERVER AND PING A CLIENT
                    if arp_req.protodst in self.user_ip_to_group.keys():
                        print("SERVER SEND ARP REQUEST TO CLIENT WE KNOW")
                        self.send_proxied_arp_reply(packet , connection , inport ,self.lb_mac)
                    else:
                        print("SERVER SEND ARP REQUEST TO CLIENT WE DONT KNOW")
                elif arp_req.protosrc in self.user_ip_to_group.keys() and arp_req.protodst == self.service_ip: #CLIENT 
                    if arp_req.protosrc not in self.clients_ip_mac.keys():
                        print("I DONT KNOW THIS CLIENT")
                        self.clients_ip_mac[arp_req.protosrc] = [arp_req.hwsrc , inport]
                        print("clietn ip mac dic = " , self.clients_ip_mac)
                    self.send_proxied_arp_reply(packet , connection , inport ,self.lb_mac)
            else:
                print("RECEIVE ARP NO REPLAY NO REQUEST")
        elif packet.type == packet.IP_TYPE:
            print("RECIEVED IP PACKED")
            print("IP SRC = " , packet.payload.srcip)
            print("IP DEST = " , packet.payload.dstip)
            # THELI KAI ENA IF PACKET.DST DEN EINAI TO IP_SERVICE NA GINETE DROP
            if packet.payload.srcip in self.clients_ip_mac.keys():
                print("CLIENT SEND IP PACKET")
                print("FLOW CLIENT TO SERVER")
                client_color = self.user_ip_to_group[packet.payload.srcip]
                print("color of client = " , client_color)
                print("inport = " , inport)
                server_ip = self.random_fun(client_color)
                print("RANDOM CHOOSE THE SEVER WITH IP = " , server_ip)
                outport = self.servers_ip_mac[server_ip][1]
                server_mac = self.servers_ip_mac[server_ip][0]
                client_ip = packet.payload.srcip
                print("serserv mac = " , server_mac)
                print("outport = " , outport)
                
                self.install_flow_rule_client_to_server(connection,inport, outport, client_ip, server_ip , server_mac)
                
            # elif packet.payload.srcip in self.server_ips:
            else:
                print("SERVER SEND IP PACKET")
                print("FLOW SERVER TO CLIENT")
                print("inport = " , inport)
                outport = self.clients_ip_mac[packet.payload.srcip][1]
                print("outport = " , outport)
                client_mac = self.clients_ip_mac[packet.payload.srcip][0]
                print("client mac = " , client_mac)
                server_ip = packet.payload.srcip
                print("server ip = " , server_ip)
                client_ip = packet.payload.dstip
                print("client ip = " , client_ip)
                self.install_flow_rule_server_to_client(connection,inport, outport, server_ip, client_ip, client_mac)
            # else:
            #     print("IP PACKET IS NOT FROM CLIENT OR SERVE")
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return


# extra function to read json files
def load_json_dict(json_file):
    json_dict = {}
    with open(json_file, 'r') as f:
        json_dict = json.load(f)
    return json_dict


# main launch routine
def launch(configuration_json_file):
    log.info("Loading Simple Load Balancer module")

    # load the configuration from file
    configuration_dict = load_json_dict(configuration_json_file)

    # the service IP that is publicly visible from the users' side
    service_ip = IPAddr(configuration_dict['service_ip'])

    # the load balancer MAC with which the switch responds to ARP requests from users/servers
    lb_mac = EthAddr(configuration_dict['lb_mac'])

    # the IPs of the servers
    server_ips = [IPAddr(x) for x in configuration_dict['server_ips']]

    # map users (IPs) to service groups (e.g., 10.0.0.5 to 'red')
    user_ip_to_group = {}
    for user_ip,group in configuration_dict['user_groups'].items():
        user_ip_to_group[IPAddr(user_ip)] = group

    # map servers (IPs) to service groups (e.g., 10.0.0.1 to 'blue')
    server_ip_to_group = {}
    for server_ip,group in configuration_dict['server_groups'].items():
        server_ip_to_group[IPAddr(server_ip)] = group

    # do the launch with the given parameters
    core.registerNew(SimpleLoadBalancer, lb_mac, service_ip, server_ips, user_ip_to_group, server_ip_to_group)
    log.info("Simple Load Balancer module loaded")

