#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController

import argparse
import sys
import time


class ClosTopo(Topo):

    def __init__(self, fanout, _cores, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        cores = []
        aggregations = []
        edges = []
        hosts = []
        # Set up Core and Aggregate level, Connection Core - Aggregation level
        #WRITE YOUR CODE HERE!
        print("cores = " , _cores)
        print("fanout = " , fanout)
        cnt_cores = 1
        cnt_agg = _cores + 1
        cnt_edd = _cores * fanout + _cores + 1
        cnt_host = 1
        for i in range(_cores):
            st1 = "core" + str(cnt_cores)
            core = self.addSwitch(st1)
            cores.append(core)
            cnt_cores += 1
            for j in range(fanout):
                st2 = "agg" + str(cnt_agg)
                agg = self.addSwitch(st2)
                aggregations.append(agg)
                cnt_agg += 1
                for k in range(fanout):
                    st3 = "edge" + str(cnt_edd)
                    edge = self.addSwitch(st3)
                    edges.append(edge)
                    cnt_edd += 1
                    for l in range(fanout):
                        st4 = "host" + str(cnt_host)
                        host = self.addHost(st4)
                        hosts.append(host)
                        self.addLink(edge , host)
                        cnt_host += 1

        for core in cores:
            for agg in aggregations:
                self.addLink(core , agg)

        for agg in aggregations:
            for edge in edges:
                self.addLink(agg , edge)

        print("cores = " , cores)
        print("agg = " , aggregations)
        print("eddd = " , edges)
        print("hhhh = " , hosts)

        # Set up Edge level, Connection Aggregation - Edge level
        #WRITE YOUR CODE HERE!
        
        # Set up Host level, Connection Edge - Host level 
        #WRITE YOUR CODE HERE!
	

def setup_clos_topo(fanout=2, cores=1):
    "Create and test a simple clos network"
    assert(fanout>0)
    assert(cores>0)
    topo = ClosTopo(fanout, cores)
    net = Mininet(topo=topo, controller=lambda name: RemoteController('c0', "127.0.0.1"), autoSetMacs=True, link=TCLink)
    net.start()
    time.sleep(20) #wait 20 sec for routing to converge
    net.pingAll()  #test all to all ping and learn the ARP info over this process
    CLI(net)       #invoke the mininet CLI to test your own commands
    net.stop()     #stop the emulation (in practice Ctrl-C from the CLI 
                   #and then sudo mn -c will be performed by programmer)

    
def main(argv):
    parser = argparse.ArgumentParser(description="Parse input information for mininet Clos network")
    parser.add_argument('--num_of_core_switches', '-c', dest='cores', type=int, help='number of core switches')
    parser.add_argument('--fanout', '-f', dest='fanout', type=int, help='network fanout')
    args = parser.parse_args(argv)
    setLogLevel('info')
    setup_clos_topo(args.fanout, args.cores)


if __name__ == '__main__':
    main(sys.argv[1:])