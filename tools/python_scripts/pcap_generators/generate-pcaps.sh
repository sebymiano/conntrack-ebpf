#!/bin/bash

NUM_CORES=6

echo "Generating PCAP for v1"
for i in {1..${NUM_CORES}}; do
    python3 generate_pcap_conntrack_v1.py -o conntrack_v1_core${i}.pcap -r -n ${i}
done

echo "Generating PCAP for v2"
for i in {1..${NUM_CORES}}; do
    python3 generate_pcap_conntrack_v2.py -o conntrack_v2_core${i}.pcap -r -n ${i}
done