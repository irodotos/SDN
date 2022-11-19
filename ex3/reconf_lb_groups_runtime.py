#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import json

from p4.v1 import p4runtime_pb2

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def byteify(input):
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def load_json(json_file):
    json_data = None
    with open(json_file, 'r') as f:
        json_data = json.load(f)
    return byteify(json_data)

def deleteSLBRules(p4info_helper, slb_sw, table_entries):
    request = p4runtime_pb2.WriteRequest()
    request.device_id = slb_sw.device_id
    request.election_id.low = 1
    for table_entry in table_entries:
        # do not delete default
        if "default_action" in table_entry:
            continue
        table_entry = p4info_helper.buildTableEntry(
            table_name=table_entry["table"],
            match_fields=table_entry["match"],
            action_name=table_entry["action_name"],
            action_params=table_entry["action_params"]
        )
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.DELETE
        update.entity.table_entry.CopyFrom(table_entry)
    slb_sw.client_stub.Write(request)

def writeSLBRules(p4info_helper, slb_sw, table_entries):
    """
    :param p4info_helper: the P4Info helper
    :param slb_sw: the load-balancer switch connection
    :param host_ip: the IP of the host
    :param group: the (new) group of the host
    """
    for table_entry in table_entries:
        if "default_action" in table_entry:
            continue
        table_entry = p4info_helper.buildTableEntry(
            table_name=table_entry["table"],
            match_fields=table_entry["match"],
            action_name=table_entry["action_name"],
            action_params=table_entry["action_params"]
        )
        slb_sw.WriteTableEntry(table_entry)

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path, slb_runtime_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # Load table entry data
        table_entries = load_json(slb_runtime_file_path)["table_entries"]

        # Clean all switch rules
        deleteSLBRules(p4info_helper, slb_sw=s1, table_entries=table_entries)

        # Adjust the rules for client or server host group membership
        writeSLBRules(p4info_helper, slb_sw=s1, table_entries=table_entries)

        # read all current table rules
        readTableRules(p4info_helper, s1)

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SLB P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/simple_load_balancer.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/simple_load_balancer.json')
    parser.add_argument('--slb-runtime', help='slb runtime file',
                        type=str, action="store", required=False,
                        default='./slb-runtime.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    if not os.path.exists(args.slb_runtime):
        parser.print_help()
        print "\nSLB-runtime file not found: %s\n" % args.slb_runtime
        parser.exit(1)
main(args.p4info, args.bmv2_json, args.slb_runtime)
