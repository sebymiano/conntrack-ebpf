#!/usr/bin/env python3

# Suppress scapy IPv6 default route message
import logging

prev_level = logging.getLogger("scapy.runtime").getEffectiveLevel()

# save prev log level
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# import modules
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.volatile import RandIP, RandString
from scapy.all import *

from scapy.utils import PcapWriter
# restore prev log level
logging.getLogger("scapy.runtime").setLevel(prev_level)

import time
from random import randint
import argparse
import yaml
import ipaddress, random, struct
from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA
import stream_helpers as helpers

from ctypes import *

widgets = [Percentage(), ' ', Bar(), ' ', ETA(), ' ', AdaptiveETA()]

class FlowKey(ctypes.Structure):
    """ creates a struct to match pkt_5tuple """
    _pack_ = 1
    _fields_ = [('src_ip', ctypes.c_uint32), ('dst_ip', ctypes.c_uint32),
                ('src_port', ctypes.c_uint16), ('dst_port', ctypes.c_uint16),
                ('proto', ctypes.c_uint8)]

    def __str__(self):
        str = f"Source IP: {ipaddress.IPv4Address(socket.ntohl(self.src_ip))}\n"
        str += f"Dest IP: {ipaddress.IPv4Address(socket.ntohl(self.dst_ip))}\n"
        str += f"Source Port: {socket.ntohs(self.src_port)}\n"
        str += f"Dst Port: {socket.ntohs(self.dst_port)}\n"
        str += f"Proto: {self.proto}\n"
        return str

    def __bytes__(self):
        flow_bytes = b''
        flow_bytes += self.src_ip.to_bytes(4, 'big')
        flow_bytes += self.dst_ip.to_bytes(4, 'big')
        flow_bytes += self.src_port.to_bytes(2, 'big')
        flow_bytes += self.dst_port.to_bytes(2, 'big')
        flow_bytes += self.proto.to_bytes(1, 'big')
        return flow_bytes


class FlowInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('flags', ctypes.c_uint8), ('seqN', ctypes.c_uint32),
                ('ackN', ctypes.c_uint32), ('timestamp', ctypes.c_uint64)]

    def __bytes__(self):
        info_bytes = b''
        info_bytes += self.flags.to_bytes(1, 'big')
        info_bytes += self.seqN.to_bytes(4, 'big')
        info_bytes += self.ackN.to_bytes(4, 'big')
        info_bytes += self.timestamp.to_bytes(8, 'big')
        return info_bytes


class MetadataElem(ctypes.Structure):
    _fields_ = [('flow', FlowKey), ('info', FlowInfo)]

    def __bytes__(self):
        md_bytes = b''
        md_bytes += bytes(self.flow)
        md_bytes += bytes(self.info)
        return md_bytes


CONFIG_file_default = f"{sys.path[0]}/../config.yaml"

def main():

    desc = """Generate pcap file for one or more TCP/IPv4 streams.
Stream characteristics (IP addresses, bitrates, packet lengths etc.)
are coded in the script file itself."""

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-i",
                        "--input-pcap",
                        type=str,
                        required=True,
                        help="The input pcap file")
    parser.add_argument("-s", "--src-mac", type=str, default="00:11:22:33:44:55", help="Source MAC address")
    parser.add_argument("-d", "--dst-mac", type=str, default="55:44:33:22:11:00", help="Destination MAC address")
    parser.add_argument("-o",
                        '--out',
                        required=True,
                        help='Output pcap file name')
    parser.add_argument("-v",
                        '--version',
                        default='v2',
                        const='v2',
                        nargs='?',
                        choices=['v2'],
                        help='v1 is for shared state, v2 is for local state')
    parser.add_argument("-n",
                        "--num-cores",
                        type=int,
                        default=0,
                        help="Number of cores")
    parser.add_argument(
        '-r',
        '--rss',
        action='store_true',
        help=
        "Increase MAC address for every packet in order to use RSS on the NIC")

    args = parser.parse_args()

    if (os.path.isfile(args.out)):
        print('"{}" already exists, refusing to overwrite.'.format(args.out))
        sys.exit(-1)

    version = args.version
    num_cores = args.num_cores
    use_mac_for_rss = args.rss

    src_mac = args.src_mac
    dst_mac = args.dst_mac

    if version == "v2":
        if num_cores <= 0:
            print("Please specify the number of cores")
            sys.exit(-1)

    input_pcap = rdpcap(args.input_pcap)

    print('{} packets in this pcap'.format(len(input_pcap)))

    total_packets = len(input_pcap)

    all_pkts = list()
    for packet in sniff(offline=args.input_pcap):
        all_pkts.append(packet)   

    all_new_pkts = list()
    count = 0
    pbar = ProgressBar(widgets=widgets, maxval=total_packets).start()
    for i, curr_pkt in enumerate(all_pkts):
        count += 1
        pbar.update(count)
        md_elem_bytes = b''
        payload = b''
        for n in reversed(range(1, num_cores)):
            flow_key = FlowKey()
            flow_info = FlowInfo()
            prev_index = i - n
            if prev_index < 0:
                flow_key.proto = 0
            else:
                pkt = all_pkts[prev_index]
                # We need to construct the previous flow information
                proto_field = pkt.getlayer(IP).proto
                flow_key.src_ip = ctypes.c_uint32(helpers.ip2int(pkt.getlayer(IP).src))
                flow_key.dst_ip = ctypes.c_uint32(helpers.ip2int(pkt.getlayer(IP).dst))
                if pkt.haslayer(TCP):
                    flow_key.src_port = ctypes.c_uint16(
                        pkt.getlayer(TCP).sport)
                    flow_key.dst_port = ctypes.c_uint16(
                        pkt.getlayer(TCP).dport)
                    flow_key.proto = ctypes.c_uint8(6)
                elif pkt.haslayer(UDP):
                    flow_key.src_port = ctypes.c_uint16(
                        pkt.getlayer(UDP).sport)
                    flow_key.dst_port = ctypes.c_uint16(
                        pkt.getlayer(UDP).dport)
                    flow_key.proto = ctypes.c_uint8(17)
                else:
                    print(
                        f"Unsupported layer type: {proto_field} ({helpers.ip_proto(pkt.payload)}"
                    )
                    sys.exit(1)

                if pkt.haslayer(TCP):
                    flow_info.flags = ctypes.c_uint8(
                        int(pkt.getlayer(TCP).flags))
                    flow_info.seqN = ctypes.c_uint32(pkt.getlayer(TCP).seq)
                    flow_info.ackN = ctypes.c_uint32(pkt.getlayer(TCP).ack)
                flow_info.timestamp = ctypes.c_uint64(int(pkt.time))

            md_elem = MetadataElem()
            md_elem.flow = flow_key
            md_elem.info = flow_info

            md_elem_bytes += bytes(md_elem)

        payload = md_elem_bytes
        if use_mac_for_rss:
            new_dst_mac = helpers.change_mac(helpers.mac_del_colons(dst_mac), i % num_cores)
        else:
            new_dst_mac = dst_mac
        new_pkt = Ether(dst = new_dst_mac, src = src_mac, type=0x800)/ \
                  Raw(load=payload)/ \
                  curr_pkt

        all_new_pkts.append(new_pkt)
    
    wrpcap(args.out, all_new_pkts)
    print("")
    print('Finished writing {} packets'.format(total_packets), flush=True)


#----------------------------------------------------------------------

if __name__ == '__main__':
    main()
