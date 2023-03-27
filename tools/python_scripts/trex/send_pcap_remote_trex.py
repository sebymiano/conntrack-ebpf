import time
from random import randint
import argparse
import yaml
import ipaddress, random, struct
import sys
import os

from trex_stl_lib.api import *
from scapy.contrib.gtp import *

def main():

    desc = """Send PCAP trace with Trex"""
    
    parser = argparse.ArgumentParser(description = desc)
    parser.add_argument("-f", "--pcap-file", type=str, required=True, help="The PCAP file")
    parser.add_argument("-p", "--port", type=int, default=0, help="Port number")
    parser.add_argument("-s", "--speedup", type=float, default=1.0, help="A factor to adjust IPG. effectively IPG = IPG / speedup")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration for the test")

    args = parser.parse_args()

    c = STLClient(server = "localhost")

    port = args.port
    speedup = args.speedup
    duration = args.duration
    
    try:
        c.connect()
        c.reset(ports = [port])

        c.set_port_attr(port, promiscuous = True) 
        print(f"Set port {port} in promiscous mode")

        # use an absolute path so the server can reach this
        pcap_file = os.path.abspath(args.pcap_file)

        c.push_remote(pcap_file,
                    ports = 0,
                    ipg_usec = 0.1,
                    count = 0,
                    speedup = speedup,
                    duration = duration)

        c.wait_on_traffic()

        stats = c.get_stats()
        ipackets = stats[port]['ipackets']
        opackets = stats[port]['opackets']

        ipackets_pps = stats[port]['ipackets'] / duration
        print("{0} packets were Tx on port {1}\n".format(opackets, port))
        print("{0} packets were Rx on port {1}\n".format(ipackets, port))

        print(f"Received {ipackets_pps}Mpps")

    except STLError as e:
        print(e)
        sys.exit(1)

    finally:
        c.disconnect()


if __name__ == '__main__':
    main()
