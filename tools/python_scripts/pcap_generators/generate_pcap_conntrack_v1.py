#!/usr/bin/env python3

# MIT License

# Copyright (c) 2018 vnetman@zoho.com
# Copyright (c) 2022 mianosebastiano@gmail.com

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

#----------------------------------------------------------------------
# The purpose of this script is to generate a single .pcap file.
#
#    ./scapy_pcap.py --out <file.pcap>
#
# The .pcap file contains packets for one or more complete TCP
# sessions (starting from the SYN handshake to the FIN/ACK
# sequence).
#
# The parameters of the TCP sessions (i.e. addresses, packet lengths,
# bitrates etc.) are coded in the script itself, because it is too
# cumbersome to specify these on the command line.
#
# It is possible to start a TCP session whilst others are in progress
# (i.e. it is not necessary to start a session only after the previous
# one has finished).
#
# Packet lengths as well as bitrates can also be specified on a
# per-session basis.
#------------------------------------------------------------------------

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


class FlowKey(ctypes.BigEndianStructure):
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


class FlowInfo(ctypes.BigEndianStructure):
    """ creates a struct to match pkt_5tuple """
    _pack_ = 1
    _fields_ = [('flags', ctypes.c_uint8), ('seqN', ctypes.c_uint32),
                ('ackN', ctypes.c_uint32), ('timestamp', ctypes.c_uint64)]


CONFIG_file_default = f"{sys.path[0]}/../config.yaml"

#----------------------------------------------------------------------


def main():

    desc = """Generate pcap file for one or more TCP/IPv4 streams.
Stream characteristics (IP addresses, bitrates, packet lengths etc.)
are coded in the script file itself."""

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-c",
                        "--config-file",
                        type=str,
                        default=CONFIG_file_default,
                        help="The YAML config file")
    parser.add_argument("-o",
                        '--out',
                        required=True,
                        help='Output pcap file name')
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

    with open(args.config_file, "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit(-1)

    num_cores = args.num_cores
    use_mac_for_rss = args.rss

    session_number = config['session_number']
    streams = []
    start_at = 0
    count = 0

    cdf_data = config['flow_size_cdf']
    cdf = [(entry['size'], entry['probability']) for entry in cdf_data]

    flow_rate_dist = config['flow_rate_distribution']

    flow_start_times = helpers.generate_flow_start_times(session_number, flow_rate_dist['mean'], flow_rate_dist['std_dev'])

    print(f"Let's start building the trace for {session_number} flows")
    pbar = ProgressBar(widgets=widgets, maxval=session_number).start()
    for i in range(session_number):
        count += 1
        pbar.update(count)
        server_ip = helpers.random_ip(config['server_ip_range'])
        client_ip = helpers.random_ip(config['client_ip_range'])
        server_mac = config['server_mac']
        client_mac = config['client_mac']
        client_port = random.randint(config['client_port_start'],
                                     config['client_port_end'])
        server_port = random.randint(config['server_port_start'],
                                     config['server_port_end'])
        bps = random.randint(config['rate_bps_start'], config['rate_bps_end'])
        num_pkt_every_connection = config['num_pkts_every_connection']
        duration = random.randint(config['duration_start'],
                                  config['duration_end'])
        packet_len = helpers.sample_flow_size(cdf)
        start_at = flow_start_times[i]
        
        s = helpers.make_tcp_stream(
            server_ip=server_ip,
            client_ip=client_ip,
            server_mac=server_mac,
            client_mac=client_mac,
            client_port=client_port,
            server_port=server_port,
            bps=bps,
            duration=duration,
            ts_first_packet=start_at,
            packet_len=packet_len,
            num_pkt_every_connection=num_pkt_every_connection)
        # start_at += duration
        # name = f"Session_{i}"
        # print('"{}" contains {} packets'.format(name, len(s)))
        streams.append(s)

    print('{} streams in this pcap'.format(len(streams)))

    # The 'all' dictionary contains information about every packet
    # that will go into the pcap.
    #
    # Key => timestamp (rendered as a string)
    # Value => list of (packet, timestamp) tuples at that timestamp
    # (since we allow more than one stream, there can be more than one
    # packet at the exact same timestamp)
    all = dict()

    total_packets = 0
    for s in streams:
        for (ts, p) in s:
            key = '%014.6f' % ts
            if not key in all:
                all[key] = []
            all[key].append((
                p,
                ts,
            ))
            total_packets = total_packets + 1

    pcap = PcapWriter(args.out, append=True, sync=False)

    rendered = 0

    # Sorting the keys of the 'all' dictionary gives us the packets in
    # the correct chronological order.
    for key in sorted(all):
        for (pkt, ts) in all[key]:

            # Make a scapy packet with the available packet
            # information.
            scapy_pkt = Ether(dst = pkt['EtherDst'], src = pkt['EtherSrc'])/ \
                        IP(dst = pkt['IpSrc'], src = pkt['IpDst'])/ \
                        TCP(sport = pkt['TcpSrc'], dport = pkt['TcpDst'], \
                            flags = pkt['TcpFlags'], seq = pkt['TcpSeqNo'])/ \
                            Raw(load = '')
            if 'TcpAckNo' in pkt:
                scapy_pkt[TCP].ack = pkt['TcpAckNo']
            else:
                scapy_pkt[TCP].ack = 0
            if 'TcpData' in pkt:
                scapy_pkt[Raw].load = pkt['TcpData']

            # Write the scapy packet to the pcap
            scapy_pkt.time = ts
            if use_mac_for_rss:
                new_mac = helpers.change_mac(
                    helpers.mac_del_colons(server_mac), rendered % num_cores)
                scapy_pkt[Ether].dst = helpers.mac_add_colons(new_mac)
                scapy_pkt[Ether].src = client_mac
            pcap.write(scapy_pkt)

            # Report progress to the impatient user
            rendered = rendered + 1
            percent = 0
            if (rendered % 1000) == 0:
                percent = int((rendered * 100.0) / total_packets)
                print('Wrote {} ({}%) of {} packets'.format(
                    rendered, percent, total_packets),
                      flush=True,
                      end='\r')

    print('Finished writing {} packets                 '.format(total_packets),
          flush=True)


#----------------------------------------------------------------------

if __name__ == '__main__':
    main()
