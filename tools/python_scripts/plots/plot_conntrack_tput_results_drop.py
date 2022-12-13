import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import argparse
import io
import sys
import os

from pdfCropMargins import crop

def create_throughput_fig(test, dir, narrow=False):
    df_v1 = pd.read_csv(f'{sys.path[0]}/../data/{dir}/throughput/results_{test}_v1_drop.csv')
    #Calculate mean across the different rows
    df_v1['mean'] = df_v1.iloc[:, 1:].mean(axis=1)

    df_v1ns = pd.read_csv(f'{sys.path[0]}/../data/{dir}/throughput/results_{test}_v1ns_drop.csv')
    #Calculate mean across the different rows
    df_v1ns['mean'] = df_v1ns.iloc[:, 1:].mean(axis=1)

    df_v2 = pd.read_csv(f'{sys.path[0]}/../data/{dir}/throughput/results_{test}_v2_drop.csv')
    #Calculate mean across the different rows
    df_v2['mean'] = df_v2.iloc[:, 1:].mean(axis=1)

    plt.rcParams.update({'font.size': 20,'lines.linewidth':1.5,'lines.markersize':10})
    #fig,ax = plt.subplots(2,1, figsize=(10,10))
    if narrow:
        fig, ax = plt.subplots(figsize=(11,4))
    else:
        fig, ax = plt.subplots(figsize=(8,5))


    plt.plot(df_v1['Cores'], df_v1['mean'], '-s', label='v1 (shared)')
    plt.plot(df_v1ns['Cores'], df_v1ns['mean'], '-+', label='v1 no locks')
    plt.plot(df_v2['Cores'], df_v2['mean'], '-^', label='v2 (local)')
    
    plt.legend()
    ax.set_ylim(bottom=0)

    plt.xlabel('# of cores')
    plt.ylabel('Packet Rate (Mpps)')
    plt.grid()

    plt.tight_layout()

    output_name = f'{sys.path[0]}/../figures/results_{test}_{dir}_drop'

    plt.savefig(f'{output_name}.pdf')

    print(f"Figure {output_name}.pdf created")

    if not narrow:
        crop(["-p", "15", "-u", "-s", "-o", f'{output_name}_cropped.pdf', f"{output_name}.pdf"])
        os.replace(f'{output_name}_cropped.pdf', f"{output_name}.pdf")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate figure for results between shared vs local version')
    parser.add_argument("-n", "--narrow", action="store_true", default=False, help="Creates a smaller figure")
    parser.add_argument("-d", "--dir", type=str, default="data-40gbps", help="Data directory where results are placed")
    args = parser.parse_args()

    # test_names = ["100flows", "10000flows", "10000flows_2pkts"]
    test_names = ["100f", "10000f", "10000f_1pkt"]
    dir = args.dir

    for test in test_names:
        create_throughput_fig(test, dir, narrow=args.narrow)
