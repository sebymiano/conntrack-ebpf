import time
from random import randint
import argparse
import yaml
import ipaddress, random, struct
from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA
import sys
import os

from trex_stl_lib.api import *
from scapy.contrib.gtp import *

def main():

    desc = """Send PCAP trace with Trex"""
    
    parser = argparse.ArgumentParser(description = desc)
    parser.add_argument("-f", "--pcap-file", type=str, required=True, help="The PCAP file")
    parser.add_argument("-p", "--port", type=int, default=0, help="Port number")

    args = parser.parse_args()

    c = STLClient(server = "localhost")

    port = args.port
    
    try:
        c.connect()
        c.reset(ports = [port])

        # use an absolute path so the server can reach this
        pcap_file = os.path.abspath(args.pcap_file)

        c.push_remote(pcap_file,
                    ports = 0,
                    ipg_usec = 100,
                    count = 1)

        c.wait_on_traffic()


        stats = c.get_stats()
        opackets = stats[port]['opackets']
        print("{0} packets were Tx on port {1}\n".format(opackets, port))

    except STLError as e:
        print(e)
        sys.exit(1)

    finally:
        c.disconnect()


if __name__ == '__main__':
    main()
