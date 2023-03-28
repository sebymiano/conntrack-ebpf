#!/usr/bin/env python3

# import modules
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.volatile import RandIP, RandString
from scapy.all import *
from random import randint
import ipaddress
import random
import struct
import random
import math


# ----------------------------------------------------------------------
def flow_arrival_rate_normal(mean, std_dev):
    flow_arrival_rate = random.normalvariate(mean, std_dev)
    return max(0, flow_arrival_rate)


# ----------------------------------------------------------------------
def generate_flow_start_times(num_flows, mean, std_dev):
    # Initialize the list of flow start times
    flow_start_times = []

    # Initialize the start time of the first flow
    current_time = 0

    # Generate the start times of the flows
    for _ in range(num_flows):
        # Calculate the flow arrival rate at the current time
        flow_arrival_rate = flow_arrival_rate_normal(mean, std_dev)

        if (flow_arrival_rate == 0):
            flow_arrival_rate = mean

        # Calculate the inter-arrival time between flows
        inter_arrival_time = 1 / flow_arrival_rate

        # Add the start time of the flow to the list
        flow_start_times.append(current_time)

        # Calculate the time when the next flow will start
        next_flow_start_time = current_time + inter_arrival_time

        current_time = next_flow_start_time

    return flow_start_times


# ----------------------------------------------------------------------
def bps_to_pps(bits_per_sec, packet_len):
    """Given a bits-per-second value, return the packets per second for the
    given packet length. Also return the time interval (in seconds) between
    successive packets"""

    packets_per_sec = (bits_per_sec / (8 * packet_len))
    inter_packet_gap_sec = 1.0 / packets_per_sec

    return (packets_per_sec, inter_packet_gap_sec)


# ----------------------------------------------------------------------
def make_tcp_stream(client_ip,
                    server_ip,
                    client_mac,
                    server_mac,
                    client_port,
                    server_port,
                    bps,
                    duration,
                    ts_first_packet,
                    packet_len,
                    num_pkt_every_connection=0):
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
    p = {
        'EtherDst': server_mac,
        'EtherSrc': client_mac,
        'IpSrc': client_ip,
        'IpDst': server_ip,
        'TcpSrc': client_port,
        'TcpDst': server_port,
        'TcpFlags': 'S',
        'TcpSeqNo': c_isn
    }
    stream.append((
        ts,
        p,
    ))
    ts = ts + 0.2

    # SYN+ACK; (s->c)
    p = {
        'EtherDst': client_mac,
        'EtherSrc': server_mac,
        'IpSrc': server_ip,
        'IpDst': client_ip,
        'TcpSrc': server_port,
        'TcpDst': client_port,
        'TcpFlags': 'SA',
        'TcpSeqNo': s_isn,
        'TcpAckNo': c_isn + 1
    }
    stream.append((
        ts,
        p,
    ))
    ts = ts + 0.2

    # ACK; (c->s)
    p = {
        'EtherDst': server_mac,
        'EtherSrc': client_mac,
        'IpSrc': client_ip,
        'IpDst': server_ip,
        'TcpSrc': client_port,
        'TcpDst': server_port,
        'TcpFlags': 'A',
        'TcpSeqNo': c_isn + 1,
        'TcpAckNo': s_isn + 1
    }
    stream.append((
        ts,
        p,
    ))
    ts = ts + 0.2

    # packet_len is inclusive of ether, ipv4 and tcp headers; check if it
    # is sane
    header_size = 14 + 20 + 20  # ether + ipv4 + tcp
    if packet_len < header_size:
        raise ValueError('Specified packet length {} is smaller than '
                         'the minimum allowed ({})'.format(
                             packet_len, header_size))

    tcp_payload_len = packet_len - header_size

    (pps, gap) = bps_to_pps(bps, packet_len)
    num_packets = int(pps * duration) + 1
    if num_pkt_every_connection != 0:
        num_packets = num_pkt_every_connection
    server_data_offset = 0

    payload = RandString(size=tcp_payload_len)

    # From this point on, server sends packets with TCP payloads, and
    # the client just acks them => client seq number does not increment

    for i in range(0, num_packets):
        # Data; (s->c)
        p = {
            'EtherDst': client_mac,
            'EtherSrc': server_mac,
            'IpSrc': server_ip,
            'IpDst': client_ip,
            'TcpSrc': server_port,
            'TcpDst': client_port,
            'TcpFlags': 'A',
            'TcpSeqNo': s_isn + 1 + server_data_offset,
            'TcpAckNo': c_isn + 1,
            'TcpData': payload
        }
        stream.append((
            ts,
            p,
        ))

        # We stick the (c->s) ack halfway between two successive data packets
        ts = ts + (gap / 2)

        server_data_offset = server_data_offset + tcp_payload_len

        # Ack; (c->s)
        p = {
            'EtherDst': server_mac,
            'EtherSrc': client_mac,
            'IpSrc': client_ip,
            'IpDst': server_ip,
            'TcpSrc': client_port,
            'TcpDst': server_port,
            'TcpFlags': 'A',
            'TcpSeqNo': c_isn + 1,
            'TcpAckNo': s_isn + 1 + server_data_offset
        }
        stream.append((
            ts,
            p,
        ))

        ts = ts + (gap / 2)

    # FIN; (s->c)
    p = {
        'EtherDst': client_mac,
        'EtherSrc': server_mac,
        'IpSrc': server_ip,
        'IpDst': client_ip,
        'TcpSrc': server_port,
        'TcpDst': client_port,
        'TcpFlags': 'F',
        'TcpSeqNo': s_isn + 1 + server_data_offset,
        'TcpAckNo': 0
    }
    stream.append((
        ts,
        p,
    ))
    ts = ts + 0.2

    # ACK; (c->s)
    p = {
        'EtherDst': server_mac,
        'EtherSrc': client_mac,
        'IpSrc': client_ip,
        'IpDst': server_ip,
        'TcpSrc': client_port,
        'TcpDst': server_port,
        'TcpFlags': 'A',
        'TcpSeqNo': c_isn + 1,
        'TcpAckNo': s_isn + 2 + server_data_offset
    }
    stream.append((
        ts,
        p,
    ))
    ts = ts + 0.2

    # FIN; (c->s)
    p = {
        'EtherDst': server_mac,
        'EtherSrc': client_mac,
        'IpSrc': client_ip,
        'IpDst': server_ip,
        'TcpSrc': client_port,
        'TcpDst': server_port,
        'TcpFlags': 'F',
        'TcpSeqNo': c_isn + 1,
        'TcpAckNo': 0
    }
    stream.append((
        ts,
        p,
    ))
    ts = ts + 0.2

    # ACK; (s->c)
    p = {
        'EtherDst': client_mac,
        'EtherSrc': server_mac,
        'IpSrc': server_ip,
        'IpDst': client_ip,
        'TcpSrc': server_port,
        'TcpDst': client_port,
        'TcpFlags': 'A',
        'TcpSeqNo': s_isn + 2 + server_data_offset,
        'TcpAckNo': c_isn + 2
    }
    stream.append((
        ts,
        p,
    ))

    return stream


# ----------------------------------------------------------------------
def random_ip(network):
    network = ipaddress.IPv4Network(network)
    # make network address into an integer
    network_int, = struct.unpack("!I", network.network_address.packed)
    # calculate the needed bits for the host part
    rand_bits = network.max_prefixlen - network.prefixlen
    rand_host_int = random.randint(0, 2**rand_bits -
                                   1)  # generate random host part
    ip_address = ipaddress.IPv4Address(network_int +
                                       rand_host_int)  # combine the parts
    return ip_address.exploded


# ----------------------------------------------------------------------
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


# ----------------------------------------------------------------------
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


# ----------------------------------------------------------------------
def ip_proto(pkt):
    proto_field = pkt.get_field('proto')
    return proto_field.i2s[pkt.proto]


# ----------------------------------------------------------------------
def change_mac(mac, offset):
    return "{:012X}".format(int(mac, 16) + offset)


# ----------------------------------------------------------------------
def mac_add_colons(mac):
    return ':'.join(mac[i:i + 2] for i in range(0, 12, 2))


# ----------------------------------------------------------------------
def mac_del_colons(mac):
    return mac.replace(':', '')


# ----------------------------------------------------------------------
def sample_flow_size(cdf):
    r = random.random()
    for size, probability in cdf:
        if r < probability:
            return size
    return cdf[-1][0]
