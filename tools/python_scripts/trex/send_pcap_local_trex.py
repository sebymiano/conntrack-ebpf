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
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration for the test")
    parser.add_argument("-r", "--rate", type=float, default=14.88, help="Rate in Mpps (float)")

    args = parser.parse_args()

    c = STLClient(server = "localhost")

    port = args.port
    rate = args.rate
    duration = args.duration
    
    try:
        c.connect()
        c.reset(ports = [port])

        c.set_port_attr(port, promiscuous = True) 
        print(f"Set port {port} in promiscous mode")

        # use an absolute path so the server can reach this
        pcap_file = os.path.abspath(args.pcap_file)

        print(f"Loading PCAP file...")
        profile = STLProfile.load_pcap(pcap_file,
                                       ipg_usec = 100,
                                       loop_count = 0)

        c.add_streams(profile.get_streams(), ports = [port])

        # clear the stats before injecting
        c.clear_stats()

        print(f"Running {rate} Mpps on ports {port} for {duration} seconds...")
        c.start(ports = [port], mult = f"{rate}mpps", duration = duration)

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
