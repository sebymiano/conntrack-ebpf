import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import argparse
import io
import sys
import os

import yaml
import statistics

from pdfCropMargins import crop

def create_bpfstats_perf_fig(test, label, narrow=False):
    try:
        with open(f'{sys.path[0]}/../data/perf/results_{test}_v1_drop.perf.yaml', "r") as stream:
            df_v1 = yaml.safe_load(stream)
        with open(f'{sys.path[0]}/../data/perf/results_{test}_v1ns_drop.perf.yaml', "r") as stream:
            df_v1ns = yaml.safe_load(stream)
        with open(f'{sys.path[0]}/../data/perf/results_{test}_v2_drop.perf.yaml', "r") as stream:
            df_v2 = yaml.safe_load(stream)
    except Exception as exc:
        print(exc)

    df_v1_metric_dict = dict()
    for core in df_v1['BPF_STATS']:
        metric_list = list()
        for metrics in df_v1['BPF_STATS'][core]:
            metric_list.append(metrics['run_time_ns']/metrics['run_cnt'])
        df_v1_metric_dict[core] = round(statistics.mean(metric_list), 2)

    df_v1ns_metric_dict = dict()
    for core in df_v1ns['BPF_STATS']:
        metric_list = list()
        for metrics in df_v1ns['BPF_STATS'][core]:
            metric_list.append(metrics['run_time_ns']/metrics['run_cnt'])
        df_v1ns_metric_dict[core] = round(statistics.mean(metric_list), 2)
    
    df_v2_metric_dict = dict()
    for core in df_v2['BPF_STATS']:
        metric_list = list()
        for metrics in df_v2['BPF_STATS'][core]:
            metric_list.append(metrics['run_time_ns']/metrics['run_cnt'])
        df_v2_metric_dict[core] = round(statistics.mean(metric_list), 2)

    plt.rcParams.update({'font.size': 20,'lines.linewidth':1.5,'lines.markersize':10})
    #fig,ax = plt.subplots(2,1, figsize=(10,10))
    if narrow:
        fig, ax = plt.subplots(figsize=(11,4))
    else:
        fig, ax = plt.subplots(figsize=(8,5))

    plt.plot(df_v1_metric_dict.keys(), df_v1_metric_dict.values(), '-s', label='v1 (shared)')
    plt.plot(df_v1ns_metric_dict.keys(), df_v1ns_metric_dict.values(), '-+', label='v1 no locks')
    plt.plot(df_v2_metric_dict.keys(), df_v2_metric_dict.values(), '-^', label='v2 (local)')
    
    plt.legend()
    ax.set_ylim(bottom=0)

    plt.xlabel('# of cores')
    plt.ylabel(label)
    plt.grid()

    plt.tight_layout()

    output_name = f'{sys.path[0]}/../figures/results_{test}_lat_drop_perf'

    plt.savefig(f'{output_name}.pdf')

    print(f"Figure {output_name}.pdf created")

    if not narrow:
        crop(["-p", "15", "-u", "-s", "-o", f'{output_name}_cropped.pdf', f"{output_name}.pdf"])
        os.replace(f'{output_name}_cropped.pdf', f"{output_name}.pdf")

def create_bpftool_perf_fig(test, metric, label, narrow=False):
    try:
        with open(f'{sys.path[0]}/../data/perf/results_{test}_v1_drop.perf.yaml', "r") as stream:
            df_v1 = yaml.safe_load(stream)
        with open(f'{sys.path[0]}/../data/perf/results_{test}_v1ns_drop.perf.yaml', "r") as stream:
            df_v1ns = yaml.safe_load(stream)
        with open(f'{sys.path[0]}/../data/perf/results_{test}_v2_drop.perf.yaml', "r") as stream:
            df_v2 = yaml.safe_load(stream)
    except Exception as exc:
        print(exc)

    df_v1_metric_dict = dict()
    for core in df_v1['BPFTOOL']:
        metric_list = list()
        for metrics in df_v1['BPFTOOL'][core]:
            metric_list.append(metrics[metric]['value']/metrics[metric]['run_cnt'])
        df_v1_metric_dict[core] = round(statistics.mean(metric_list), 2)

    df_v1ns_metric_dict = dict()
    for core in df_v1ns['BPFTOOL']:
        metric_list = list()
        for metrics in df_v1ns['BPFTOOL'][core]:
            metric_list.append(metrics[metric]['value']/metrics[metric]['run_cnt'])
        df_v1ns_metric_dict[core] = round(statistics.mean(metric_list), 2)
    
    df_v2_metric_dict = dict()
    for core in df_v2['BPFTOOL']:
        metric_list = list()
        for metrics in df_v2['BPFTOOL'][core]:
            metric_list.append(metrics[metric]['value']/metrics[metric]['run_cnt'])
        df_v2_metric_dict[core] = round(statistics.mean(metric_list), 2)

    plt.rcParams.update({'font.size': 20,'lines.linewidth':1.5,'lines.markersize':10})
    #fig,ax = plt.subplots(2,1, figsize=(10,10))
    if narrow:
        fig, ax = plt.subplots(figsize=(11,4))
    else:
        fig, ax = plt.subplots(figsize=(8,5))

    plt.plot(df_v1_metric_dict.keys(), df_v1_metric_dict.values(), '-s', label='v1 (shared)')
    plt.plot(df_v1ns_metric_dict.keys(), df_v1ns_metric_dict.values(), '-+', label='v1 no locks')
    plt.plot(df_v2_metric_dict.keys(), df_v2_metric_dict.values(), '-^', label='v2 (local)')
    
    plt.legend()
    ax.set_ylim(bottom=0)

    plt.xlabel('# of cores')
    plt.ylabel(label)
    plt.grid()

    plt.tight_layout()

    output_name = f'{sys.path[0]}/../figures/results_{test}_{metric}_drop_perf'

    plt.savefig(f'{output_name}.pdf')

    print(f"Figure {output_name}.pdf created")

    if not narrow:
        crop(["-p", "15", "-u", "-s", "-o", f'{output_name}_cropped.pdf', f"{output_name}.pdf"])
        os.replace(f'{output_name}_cropped.pdf', f"{output_name}.pdf")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate figure for results between shared vs local version')
    parser.add_argument("-n", "--narrow", action="store_true", default=False, help="Creates a smaller figure")
    args = parser.parse_args()

    test_names = ["100f", "10000f", "10000f_2pkts"]

    for test in test_names:
        create_bpftool_perf_fig(test, "cycles", "# of cycles", narrow=args.narrow)
        create_bpftool_perf_fig(test, "dtlb_misses", "# of dtlb_misses", narrow=args.narrow)
        create_bpftool_perf_fig(test, "instructions", "# of instructions", narrow=args.narrow)
        create_bpftool_perf_fig(test, "llc_misses", "# of llc_misses", narrow=args.narrow)

        create_bpfstats_perf_fig(test, "ns latency", narrow=args.narrow)
        
