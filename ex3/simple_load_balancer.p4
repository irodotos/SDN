/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** CONSTANTS  **************************************
*************************************************************************/

const bit<16> TYPE_IPV4     = 0x800;
const bit<16> TYPE_ARP      = 0x806;
const bit<32> serviceIP     = 0xa010203;
const bit<48> lbMAC         = 0xa0000000001;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/* type definitions for ease of reference */
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* ethernet frame header */
header ethernet_t {
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    bit<16>     etherType;
}

/* ARP packet header */
header arp_t {
    bit<16>     hwType;
    bit<16>     protoType;
    bit<8>      hwAddrLen;
    bit<8>      protoAddrLen;
    bit<16>     opCode;
    macAddr_t   hwSrcAddr;
    ip4Addr_t   protoSrcAddr;
    macAddr_t   hwDstAddr;
    ip4Addr_t   protoDstAddr;
}

/* IP packet header */
header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    ip4Addr_t   srcAddr;
    ip4Addr_t   dstAddr;
}

/* metadata carried by the packet through the processing pipelines */
struct metadata {
    macAddr_t   dstMAC;         // the dst MAC to which the packet should be directed on L2
    bit<1>      isClient;       // whether the src IP of the packet belongs to a client
    bit<1>      isServer;       // whether the src IP of the packet belongs to a server
    bit<8>      srcGroup;       // the group of the src host
    bit<8>      dstGroup;       // the group of the dst host
}

struct headers {
    ethernet_t  ethernet;
    arp_t       arp;
    ipv4_t      ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SLBParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    /* begin with pointing to Ethernet frame parser */
    state start {
        transition parse_ethernet;
    }

    /* parser ethernet frame */
    state parse_ethernet {
        /* WRITE YOUR CODE HERE */
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;          // accept; the ARP packet will be pushed to ingress pipeline
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);   // accept; the IP packet will be pushed to ingress pipeline
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control SLBVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SLBIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

    /* Action that instructs the pipeline to drop a packet */
    action drop() {
        mark_to_drop(standard_metadata);
    }

    /* Action that transforms an ARP request into a suitable ARP reply */
    action arp_request_to_reply(macAddr_t srcMAC, macAddr_t dstMAC, ip4Addr_t srcIP, ip4Addr_t dstIP) {
        /* WRITE YOUR CODE HERE */
        standard_metadata.egress_spec = standard_metadata.ingress_port; // the reply should be sent out of the in-port
    }

    /* Action that stores the dst MAC in the metadata and sets the port to which the packet should be sent */
    action set_egress_metadata(macAddr_t dstMAC, egressSpec_t port) {
        meta.dstMAC = dstMAC;
        standard_metadata.egress_spec = port;
    }

    /* Action that updates metadata with the info that the src IP is a client and to which server the client is mapped */
    action set_client_metadata(ip4Addr_t firstAllowedReplica, ip4Addr_t lastAllowedReplica) {
        meta.isClient = 1;
        meta.isServer = 0;
        /* WRITE YOUR CODE HERE */
    }

    /* Action that updates metadata with the info that the src IP does not belong to a client */
    action unset_client_metadata() {
        meta.isClient = 0;
    }

    /* Action that updates metadata with the info that the src IP belongs to a server */
    action set_server_metadata() {
        meta.isServer = 1;
        meta.isClient = 0;
    }

    /* Action that updates metadata with the info that the src IP does not belong to a server */
    action unset_server_metadata() {
        meta.isServer = 0;
    }

    /* Action that sets the group membership for a src host */
    action set_src_membership(bit<8> group) {
        meta.srcGroup = group;
    }

    /* Action that sets the group membership for a dst host */
    action set_dst_membership(bit<8> group) {
        meta.dstGroup = group;
    }

    /* Table that stores the mapping between dst IP and dst MAC and egress port */
    table arpmap {
        /* WRITE YOUR CODE HERE */
    }

    /* Table that stores the info that a certain IP belongs to a client */
    table ipv4_clients {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            set_client_metadata;
            unset_client_metadata;
        }
    }

    /* Table that stores the info that a certain IP belongs to a server */
    table ipv4_servers {
        /* WRITE YOUR CODE HERE */
    }

    /* Table that stores the info about which src IP is member of which group */
    table src_group_membership {
        /* WRITE YOUR CODE HERE */
    }

    /* Table that stores the info about which dst IP is member of which group */
    table dst_group_membership {
        /* WRITE YOUR CODE HERE */
    }

    /* Apply ingress workflow */
    apply {
        if (!(hdr.arp.isValid() || hdr.ipv4.isValid())) {
            drop();                                                         // drop irrelevant/invalid traffic
        }
        else if (hdr.arp.isValid() && hdr.arp.opCode == 1) {                // handle incoming ARP requests
            /* WRITE YOUR CODE HERE */
        }
        else if (hdr.ipv4.isValid()) {
            /* WRITE YOUR CODE HERE */
            if (!((meta.isClient == 1) || meta.isServer == 1) || meta.srcGroup != meta.dstGroup) {
                drop();                                                     // drop if not coming from client or server
            }                                                               // of if the src/dst groups differ
            else {
                arpmap.apply();                                             // prepare for egress
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SLBEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* Action that rewrites the header of client-to-server packets */
    action rewrite_client_to_server() {
       /* WRITE YOUR CODE HERE */
    }

    /* Action that rewrites the header of server-to-client packets */
    action rewrite_server_to_client() {
       /* WRITE YOUR CODE HERE */
    }

    /* Apply egress workflow */
    apply {
        if (hdr.ipv4.isValid()) {
            /* WRITE YOUR CODE HERE */
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control SLBComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control SLBDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);  // emit ethernet frame
        packet.emit(hdr.arp);       // emit ARP packet
        packet.emit(hdr.ipv4);      // emit IP packet
    }
}

/*************************************************************************
***********************  S W I T C H (SLB)  *****************************
*************************************************************************/

V1Switch(
    SLBParser(),            // parse packet headers
    SLBVerifyChecksum(),    // verify thet the packet is valid
    SLBIngress(),           // apply ingress logic
    SLBEgress(),            // apply egress logic
    SLBComputeChecksum(),   // compute the new checksum for the IP packet
    SLBDeparser()           // deparse (serialize) the packet
) main;
