#!/bin/bash

tests=("100f" "10000f" "10000f_2pkts")
versions=("v1" "v1ns" "v2")

for test in ${tests[@]}; do
  for version in ${versions[@]}; do
    python3 run_test_different_cores.py -c config_test_${test}.yaml -v ${version} -n 6 -d 60 -o results_${test}_${version}_redir.csv -r 3 -a REDIR -p BPFTOOL -p BPF_STATS
    python3 run_test_different_cores.py -c config_test_${test}.yaml -v ${version} -n 6 -d 60 -o results_${test}_${version}_drop.csv -r 3 -a DROP -p BPFTOOL -p BPF_STATS
  done
done