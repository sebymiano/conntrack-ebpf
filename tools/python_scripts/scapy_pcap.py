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

# The 'stream_specs' tuple defined below is used to generate a set of
# streams like this (X axis is time in seconds, e.g. Stream C starts
# at offset 140 seconds and lasts 150 seconds (i.e. upto the 290
# second mark)): 
#
#
#           0                                300
# Stream A: |---------------------------------| 30kbps
#                                               Packet len = 1400 bytes 
#
#             10          120
# Stream B:    |-----------|                    1Mbps
#                                               Packet len = 580 bytes
#
#                           140            290
# Stream C:                  |--------------|   200kbps
#                                               Packet len = 700 bytes
#
#                       110   145     
# Stream D:              |-----|                4Mbps
#                                               Packet len = 100 bytes
#
#                            142 146
# Stream E:                   |--|              20Mbps
#                                               Packet len = 70 bytes

# The sessions are specified here. Modify to suit.
#
stream_specs = (

    {'name'          : 'Stream A',
     'server_ip'     : '1.1.1.14',
     'client_ip'     : '1.1.1.11',
     'server_mac'    : '00:00:0c:01:01:14',
     'client_mac'    : '00:00:0c:01:01:11',
     'server_port'   : 80,
     'client_port'   : 1050,
     'rate_bps'      : 30 * 1000,
     'packet_length' : 1400,
     'duration'      : 300,
     'start_at'      : 0},

    {'name'          : 'Stream B',
     'server_ip'     : '1.1.1.15',
     'client_ip'     : '1.1.1.13',
     'server_mac'    : '00:00:0c:01:01:15',
     'client_mac'    : '00:00:0c:01:01:13',
     'server_port'   : 80,
     'client_port'   : 1051,
     'rate_bps'      : 1 * 1000 * 1000,
     'packet_length' : 580,
     'duration'      : 120 - 10,
     'start_at'      : 10},

    {'name'          : 'Stream C',
     'server_ip'     : '1.1.1.15',
     'client_ip'     : '1.1.1.11',
     'server_mac'    : '00:00:0c:01:01:15',
     'client_mac'    : '00:00:0c:01:01:11',
     'server_port'   : 80,
     'client_port'   : 1052,
     'rate_bps'      : 200 * 1000,
     'packet_length' : 700,
     'duration'      : 290 - 140,
     'start_at'      : 140},

    {'name'          : 'Stream D',
     'server_ip'     : '1.1.1.14',
     'client_ip'     : '1.1.1.13',
     'server_mac'    : '00:00:0c:01:01:14',
     'client_mac'    : '00:00:0c:01:01:13',
     'server_port'   : 8080,
     'client_port'   : 1053,
     'rate_bps'      : 4 * 1000 * 1000,
     'packet_length' : 100,
     'duration'      : 145 - 110,
     'start_at'      : 110},

    {'name'          : 'Stream E',
     'server_ip'     : '1.1.1.14',
     'client_ip'     : '1.1.1.13',
     'server_mac'    : '00:00:0c:01:01:14',
     'client_mac'    : '00:00:0c:01:01:13',
     'server_port'   : 443,
     'client_port'   : 1054,
     'rate_bps'      : 20 * 1000 * 1000,
     'packet_length' : 70,
     'duration'      : 146 - 142,
     'start_at'      : 142},)
    
#----------------------------------------------------------------------

def bps_to_pps(bits_per_sec, packet_len):
    """Given a bits-per-second value, return the packets per second for the
    given packet length. Also return the time interval (in seconds) between
    successive packets"""
    
    packets_per_sec = (bits_per_sec / (8 * packet_len))
    inter_packet_gap_sec = 1.0 / packets_per_sec

    return (packets_per_sec, inter_packet_gap_sec)
#----------------------------------------------------------------------

def make_tcp_stream(client_ip, server_ip, client_mac, server_mac,
                    client_port, server_port, bps, duration,
                    ts_first_packet, packet_len):
    """Return an array of 2-tuples, each 2-tuple representing a packet. The
    first member of each tuple is the timestamp (at which it is inserted in the
    pcap), and the second member is a dictionary that contains packet
    information (src & dest ip addresses, tcp ack & seq numbers, etc.)"""

    stream = []

    ts = ts_first_packet

    # Random TCP sequence numbers
    c_isn = randint(1000, 1000000)
    s_isn = randint(1000, 1000000)

    # SYN; (c->s)
    p = { 'EtherDst' : server_mac,
          'EtherSrc' : client_mac,
          'IpSrc'    : client_ip,
          'IpDst'    : server_ip,
          'TcpSrc'   : client_port,
          'TcpDst'   : server_port,
          'TcpFlags' : 'S',
          'TcpSeqNo' : c_isn }
    stream.append((ts, p,))
    ts = ts + 0.2

    # SYN+ACK; (s->c)
    p = { 'EtherDst' : client_mac,
          'EtherSrc' : server_mac,
          'IpSrc'    : server_ip,
          'IpDst'    : client_ip,
          'TcpSrc'   : server_port,
          'TcpDst'   : client_port,
          'TcpFlags' : 'SA',
          'TcpSeqNo' : s_isn,
          'TcpAckNo' : c_isn + 1 }
    stream.append((ts, p,))
    ts = ts + 0.2
    
    # ACK; (c->s)
    p = { 'EtherDst' : server_mac,
          'EtherSrc' : client_mac,
          'IpSrc'    : client_ip,
          'IpDst'    : server_ip,
          'TcpSrc'   : client_port,
          'TcpDst'   : server_port,
          'TcpFlags' : 'A',
          'TcpSeqNo' : c_isn + 1,
          'TcpAckNo' : s_isn + 1 }
    stream.append((ts, p,))
    ts = ts + 0.2

    # packet_len is inclusive of ether, ipv4 and tcp headers; check if it
    # is sane
    header_size = 14 + 20 + 20 # ether + ipv4 + tcp
    if packet_len < header_size:
        raise ValueError('Specified packet length {} is smaller than '
                         'the minimum allowed ({})'.
                         format(packet_len, header_size))

    tcp_payload_len = packet_len - header_size

    (pps, gap) = bps_to_pps(bps, packet_len)
    num_packets = int(pps * duration) + 1
    server_data_offset = 0

    payload = RandString(size = tcp_payload_len)
    
    # From this point on, server sends packets with TCP payloads, and
    # the client just acks them => client seq number does not increment 

    for i in range(0, num_packets):
        # Data; (s->c)
        p = { 'EtherDst' : client_mac,
              'EtherSrc' : server_mac,
              'IpSrc'    : server_ip,
              'IpDst'    : client_ip,
              'TcpSrc'   : server_port,
              'TcpDst'   : client_port,
              'TcpFlags' : 'A',
              'TcpSeqNo' : s_isn + 1 + server_data_offset,
              'TcpAckNo' : c_isn + 1,
              'TcpData'  : payload }
        stream.append((ts, p,))

        # We stick the (c->s) ack halfway between two successive data packets
        ts = ts + (gap/2)
        
        server_data_offset = server_data_offset + tcp_payload_len

        # Ack; (c->s)
        p = { 'EtherDst' : server_mac,
              'EtherSrc' : client_mac,
              'IpSrc'    : client_ip,
              'IpDst'    : server_ip,
              'TcpSrc'   : client_port,
              'TcpDst'   : server_port,
              'TcpFlags' : 'A',
              'TcpSeqNo' : c_isn + 1,
              'TcpAckNo' : s_isn + 1 + server_data_offset }
        stream.append((ts, p,))

        ts = ts + (gap/2)

    # FIN; (s->c)
    p = { 'EtherDst' : client_mac,
          'EtherSrc' : server_mac,
          'IpSrc'    : server_ip,
          'IpDst'    : client_ip,
          'TcpSrc'   : server_port,
          'TcpDst'   : client_port,
          'TcpFlags' : 'F',
          'TcpSeqNo' : s_isn + 1 + server_data_offset,
          'TcpAckNo' : 0 }
    stream.append((ts, p,))
    ts = ts + 0.2

    # ACK; (c->s)
    p = { 'EtherDst' : server_mac,
          'EtherSrc' : client_mac,
          'IpSrc'    : client_ip,
          'IpDst'    : server_ip,
          'TcpSrc'   : client_port,
          'TcpDst'   : server_port,
          'TcpFlags' : 'A',
          'TcpSeqNo' : c_isn + 1,
          'TcpAckNo' : s_isn + 2 + server_data_offset }
    stream.append((ts, p,))
    ts = ts + 0.2

    # FIN; (c->s)
    p = { 'EtherDst' : server_mac,
          'EtherSrc' : client_mac,
          'IpSrc'    : client_ip,
          'IpDst'    : server_ip,
          'TcpSrc'   : client_port,
          'TcpDst'   : server_port,
          'TcpFlags' : 'F',
          'TcpSeqNo' : c_isn + 1,
          'TcpAckNo' : 0 }
    stream.append((ts, p,))
    ts = ts + 0.2

    # ACK; (s->c)
    p = { 'EtherDst' : client_mac,
          'EtherSrc' : server_mac,
          'IpSrc'    : server_ip,
          'IpDst'    : client_ip,
          'TcpSrc'   : server_port,
          'TcpDst'   : client_port,
          'TcpFlags' : 'A',
          'TcpSeqNo' : s_isn + 2 + server_data_offset,
          'TcpAckNo' : c_isn + 2 }
    stream.append((ts, p,))
    
    return stream
#----------------------------------------------------------------------

def main():

    desc = """Generate pcap file for one or more TCP/IPv4 streams.
Stream characteristics (IP addresses, bitrates, packet lengths etc.)
are coded in the script file itself."""
    
    parser = argparse.ArgumentParser(description = desc)

    parser.add_argument('--out', required = True,
                        metavar = '<output pcap file name>')

    args = parser.parse_args()

    if (os.path.isfile(args.out)):
        print('"{}" already exists, refusing to overwrite.'.format(args.out))
        sys.exit(-1)
    
    streams = []
    for ss in stream_specs:
        s = make_tcp_stream(server_ip = ss['server_ip'],
                            client_ip = ss['client_ip'],
                            server_mac = ss['server_mac'],
                            client_mac = ss['client_mac'],
                            client_port = ss['client_port'],
                            server_port = ss['server_port'],
                            bps = ss['rate_bps'],
                            duration = ss['duration'],
                            ts_first_packet = ss['start_at'],
                            packet_len = ss['packet_length'])
        
        print('"{}" contains {} packets'.format(ss['name'], len(s)))
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
            all[key].append((p, ts,))
            total_packets = total_packets + 1
        
    pcap = PcapWriter(args.out, append = True, sync = False)

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
            pcap.write(scapy_pkt)

            # Report progress to the impatient user
            rendered = rendered + 1
            percent = 0
            if (rendered % 1000) == 0:
                percent = int((rendered * 100.0)/total_packets)
                print('Wrote {} ({}%) of {} packets'.
                      format(rendered, percent, total_packets),
                      flush = True, end = '\r')
                
    print('Finished writing {} packets                 '.format(total_packets),
          flush = True)
#----------------------------------------------------------------------

if __name__ == '__main__':
    main()