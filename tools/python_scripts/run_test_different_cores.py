import argparse
import yaml
import sys
import os
import paramiko
import time
import subprocess
import pandas as pd
import numpy as np
import errno
import os
from datetime import datetime
import shutil
import json

import logging
from logger import CustomFormatter

CONFIG_file_default = f"{sys.path[0]}/config_test.yaml"

logger = logging.getLogger("Test_conntrack")
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

ch.setFormatter(CustomFormatter())

logger.addHandler(ch)

def kill_conntrack_bin(client, version):
    if version == "v1" or version == "v1ns":
        conntrack_bin_name = "conntrack"
    else:
        conntrack_bin_name = "conntrack_v2"
    _, ssh_stdout, _ = client.exec_command(f"sudo pkill {conntrack_bin_name}")
    return ssh_stdout.channel.recv_exit_status()

def kill_tmux_session(client, session_name):
    _, ssh_stdout, _ = client.exec_command(f"tmux kill-session -t {session_name}")
    return ssh_stdout.channel.recv_exit_status()

def remove_xdp_from_iface(client, iface):
    _, ssh_stdout, _ = client.exec_command(f"sudo ip link set {iface} xdp off")
    return ssh_stdout.channel.recv_exit_status()

def clean_environment(client, version, remote_iface):
    kill_conntrack_bin(client, version)
    kill_tmux_session(client, "conntrack")
    remove_xdp_from_iface(client, remote_iface)
    client.exec_command(f"sudo sysctl -w kernel.bpf_stats_enabled=0")

def copy_file_from_remote_host(client, remote_file, local_file):
    logger.debug(f"Copy files from {remote_file} to {local_file}")
    ftp_client=client.open_sftp()
    ftp_client.get(remote_file, local_file)

    client.exec_command(f"sudo rm {remote_file}")

    ftp_client.close()

def init_remote_client(client, remote_conntrack_path, remote_iface, core, version, action, duration, stats_file_name, use_mac_for_rss, start_mac, disable_ht, disable_cstates):
    #make sure we start from a clean environment
    clean_environment(client, version, remote_iface)

    if not use_mac_for_rss:
        _, ssh_stdout, _ = client.exec_command(f"sudo -S ethtool -L {remote_iface} combined {core}")
        if ssh_stdout.channel.recv_exit_status() == 0:
            logger.debug(f"Changed NIC queues to {core}")
        else:
            raise Exception("Error while executing ethtool command")
    else:
        logger.info(f"Running remote cmd: sudo {remote_conntrack_path}/tools/set_rss_mac.sh {remote_iface} {core} {start_mac}")
        _, ssh_stdout, _ = client.exec_command(f"sudo {remote_conntrack_path}/tools/set_rss_mac.sh {remote_iface} {core} {start_mac}")
        if ssh_stdout.channel.recv_exit_status() == 0:
            logger.debug(f"Set RSS for {core} cores")
        else:
            raise Exception("Error while executing set_rss_mac.sh script")

    if disable_ht:
        logger.info(f"sudo {remote_conntrack_path}/tools/disable_ht.sh 1")
        _, ssh_stdout, _ = client.exec_command(f"sudo {remote_conntrack_path}/tools/disable_ht.sh 1")
        if ssh_stdout.channel.recv_exit_status() == 0:
            logger.debug(f"Hyper threading disabled")
        else:
            raise Exception("Error while executing disable_ht.sh script")

    if disable_cstates:
        logger.info("Let's disable cstates")
        _, ssh_stdout, _ = client.exec_command(f"sudo {remote_conntrack_path}/tools/set_cpu_frequency.sh")
        if ssh_stdout.channel.recv_exit_status() == 0:
            logger.debug(f"Cstates disabled")
        else:
            raise Exception("Error while executing set_cpu_frequency.sh script")   

    # Adding 60 seconds to make sure the system will setup everything before closing the test
    new_duration = duration + 60
    if version == "v1":
        conntrack_bin_name = "conntrack"
        conntrack_bin = f"{remote_conntrack_path}/src/{conntrack_bin_name}"
        if action == "DROP":
            conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -d {new_duration} -o {stats_file_name}"
        else:    
            conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -q -r -d {new_duration}"
    elif version == "v1ns":
        conntrack_bin_name = "conntrack"
        conntrack_bin = f"{remote_conntrack_path}/src/{conntrack_bin_name}"
        if action == "DROP":
            conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -s -d {new_duration} -o {stats_file_name}"
        else:    
            conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -s -q -r -d {new_duration}"
    else:
        conntrack_bin_name = "conntrack_v2"
        conntrack_bin = f"{remote_conntrack_path}/src/{conntrack_bin_name}"
        if action == "DROP":
            conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -n {core} -d {new_duration} -o {stats_file_name}"
        else:
            conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -q -r -n {core} -d {new_duration}"

    _, ssh_stdout, _ = client.exec_command(f"tmux new-session -d -s conntrack 'sudo {conntrack_cmd}'")

    logger.info("Command sent to remote server, let's wait until it starts")
    logger.info(f"Remote cmd: {conntrack_cmd}")
    time.sleep(30)
    
    _, ssh_stdout, _ = client.exec_command(f"pgrep {conntrack_bin_name}")
    cmd_output = ssh_stdout.readlines()
    if not cmd_output:
        raise Exception("Conntrack command not executed successfully")
    else:
        logger.debug("Conntrack command executed successfully")


    logger.info("Let's now set the core affinity")
    _, ssh_stdout, _ = client.exec_command(f"sudo {remote_conntrack_path}/tools/set_irq_affinity.sh local {remote_iface}")
    if ssh_stdout.channel.recv_exit_status() == 0:
        logger.debug(f"Set correct core affinity")
    else:
        kill_tmux_session(client, "conntrack")
        raise Exception("Error while setting core affinity")   


def start_prog_profile(client, profile, bpf_prog_name, profile_path, duration, sleep_timeout):
    if profile == "BPFTOOL":
        profile_cmd = f"sleep {sleep_timeout} && sudo bpftool --json --pretty prog profile name {bpf_prog_name} duration {duration} cycles instructions llc_misses dtlb_misses > {profile_path}"
    elif profile == "BPF_STATS":
        client.exec_command(f"sudo sysctl -w kernel.bpf_stats_enabled=1")
        profile_cmd = f"sleep {duration} && sudo bpftool prog list name {bpf_prog_name} --json --pretty > {profile_path}; sudo sysctl -w kernel.bpf_stats_enabled=0"
    else:
        raise Exception(f"Profile type {profile} not currently supported")  

    logger.debug(f"Running BPF profile with cmd: {profile_cmd}")
    client.exec_command(f"{profile_cmd}")

def parse_dpdk_results(stats_file_name, duration):
    if duration <= 10:
        gap = 2
    elif duration > 10 and duration < 30:
        gap = 5
    else:
        gap = 10
    df = pd.read_csv(stats_file_name)
    # Discard 10 elements at beginning and at end
    mpps = round(np.mean(df["RX-packets"][gap:-gap])/1e6, 2)
    return mpps

def parse_perf_results(profile, profile_name):
    with open(profile_name, 'r') as f:
        results = dict()
        data = json.load(f)
        if profile == "BPFTOOL":
            for v in data:
                results[v["metric"]] = dict()
                results[v["metric"]]["run_cnt"] = v["run_cnt"]
                results[v["metric"]]["value"] = v["value"]
        elif profile == "BPF_STATS":
            results["run_time_ns"] = data["run_time_ns"]
            results["run_cnt"] = data["run_cnt"]
        else:
            raise Exception(f"Profile type {profile} not currently supported")
    
    return results

def main():
    desc = """Run test for conntrack_bpf with different number of cores"""
    
    parser = argparse.ArgumentParser(description = desc)
    parser.add_argument("-c", "--config-file", type=str, default=CONFIG_file_default, help="The YAML config file")
    parser.add_argument("-o", '--out', type=str, required = True, help='Output file name')
    parser.add_argument('--out-dir', type=str, help='Directory where to place results')
    parser.add_argument("-v", '--version', default='v1', const='v1', nargs='?', choices=['v1', 'v1ns', 'v2'], help='v1 is for shared state, v1ns is for shared state without spin locks, v2 is for local state')
    parser.add_argument("-n", "--num-cores", type=int, required = True, help="Max number of cores. The test will start from 1 to this value")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration of the test")
    parser.add_argument("-r", "--runs", type=int, default=5, help="Number of runs for each test")
    parser.add_argument("-a", '--action', default='REDIR', const='REDIR', nargs='?', choices=['REDIR', 'DROP'], help='REDIR is to redirect packets on the same iface, DROP is to drop all pkts')
    parser.add_argument("-p", '--profiles', nargs='?', choices=['NONE', 'BPFTOOL', 'BPF_STATS', 'PERF'], action='append', help='NONE does not perform any profiling, BPFTOOL uses bpftool profile to get stats about the running program, PERF uses Linux perf tool')
    parser.add_argument('-m', '--mac-rss', action='store_true', help="Increase MAC address for every packet in order to use RSS on the NIC")
    parser.add_argument('--disable-ht', action='store_true', help="Disable Hyper-Threading")
    parser.add_argument('--disable-cstates', action='store_true', help="Disable CStates")

    args = parser.parse_args()

    if (os.path.isfile(args.out)):
        print('"{}" already exists, refusing to overwrite.'.format(args.out))
        sys.exit(-1)

    with open(args.config_file, "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            logger.critical(exc)
            sys.exit(-1)

    version = args.version
    num_cores = args.num_cores
    duration = args.duration
    runs = args.runs
    output_filename = args.out
    action = args.action
    profiles = args.profiles
    out_dir = args.out_dir
    use_mac_for_rss = args.mac_rss
    disable_ht = args.disable_ht
    disable_cstates = args.disable_cstates

    if profiles is None:
        profiles = list()
        profiles.append("NONE")

    if duration < 30:
        logger.warning("Duration of the test is too short. Test might not work properly")

    remote_host = config["remote_host"]
    remote_user = config["remote_user"]
    remote_conntrack_path = config["remote_conntrack_path"]
    remote_iface = config["remote_iface"]
    local_iface_pci_id = config["local_iface_pci_id"]
    local_numa_core = config["local_numa_core"]
    remote_bpf_prog_name = config["remote_bpf_prog_name"]
    server_mac = config["server_mac"]

    if ("local_private_key" not in config) or (not config["local_private_key"]):
        logger.warning("The YAML file does not provide any private key.")
        default_path = os.path.join(os.environ["HOME"], ".ssh", "id_rsa")
        logger.info(f"I'll use the default key from: {default_path}")
        local_private_key = default_path
    else:
        local_private_key = config["local_private_key"]

    final_results_tput = dict()
    final_results_perf = dict()

    if not out_dir:
        out_dir = os.path.join(
            os.getcwd(), 
            datetime.now().strftime(f'{os.path.splitext(output_filename)[0]}-%Y-%m-%d_%H-%M-%S'))
    raw_test_dir = os.path.join(out_dir, "raw")
    try:
        os.makedirs(raw_test_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise  # This was not a "directory exist" error..

    for profile in profiles:
        final_results_perf[profile] = dict()
        for core in range(1, num_cores + 1):
            final_results_tput[core] = list()
            final_results_perf[profile][core] = list()
            for run in range(runs):
                pcap_path_found = False
                pcap_path = ""

                for pcap in config["local_pcaps"]:
                    if int(pcap["core"]) == core:
                        pcap_path = pcap[f"{version}_path"]
                        pcap_path_found = True
                        break
                    
                if not pcap_path_found:
                    logger.error(f"No pcap path found for core: {core}")
                    continue

                try:
                    client = paramiko.SSHClient()
                    k = paramiko.RSAKey.from_private_key_file(local_private_key)

                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    try:
                        client.connect(hostname=remote_host, username=remote_user, pkey=k)
                    except Exception as e:
                        logger.critical("Failed to connect. Exit!")
                        logger.critical("*** Caught exception: %s: %s" % (e.__class__, e))
                        sys.exit(1)

                    stats_file_name = f"result_{version}_core{core}_run{run}_{action}.csv"
                    init_remote_client(client, remote_conntrack_path, remote_iface, core, version, action, duration, f"{remote_conntrack_path}/src/{stats_file_name}", use_mac_for_rss, server_mac, disable_ht, disable_cstates)

                    if action == "DROP":
                        pktgen_cmd = (f"sudo dpdk-replay --nbruns 100000000 --numacore {local_numa_core} "
                                    f"--timeout {duration} --stats {local_iface_pci_id} "
                                    f"{pcap_path} {local_iface_pci_id}")
                    else:
                        pktgen_cmd = (f"sudo dpdk-replay --nbruns 100000000 --numacore {local_numa_core} "
                                    f"--timeout {duration} --stats {local_iface_pci_id} "
                                    f"--stats-name {stats_file_name} --write-csv {pcap_path} {local_iface_pci_id}")

                    if profile == "BPFTOOL":
                        profile_name = f"result_{version}_core{core}_run{run}_{action}_profile_{profile}.json"
                        profile_path = f"{remote_conntrack_path}/src/{profile_name}"
                        start_prog_profile(client, profile, remote_bpf_prog_name, profile_path, duration - 10, 10)
                    elif profile == "BPF_STATS":
                        profile_name = f"result_{version}_core{core}_run{run}_{action}_profile_{profile}.txt"
                        profile_path = f"{remote_conntrack_path}/src/{profile_name}"
                        start_prog_profile(client, profile, remote_bpf_prog_name, profile_path, duration - 10, 10)

                    logger.debug(f"Executing local pktgen command: {pktgen_cmd}")
                    generator_run = subprocess.run(pktgen_cmd.split())
                    logger.debug(f"The exit code was: {generator_run.returncode}")

                    if action == "DROP":
                        logger.debug("Going to sleep for 60s, waiting for the remote to save results")
                        time.sleep(45)
                        copy_file_from_remote_host(client, f"{remote_conntrack_path}/src/{stats_file_name}", f"{sys.path[0]}/{stats_file_name}")

                    if profile != "NONE":
                        copy_file_from_remote_host(client, f"{profile_path}", f"{sys.path[0]}/{profile_name}")
                        logger.debug(f"Let's check if the result file: {profile_name} has been created.")
                        if os.path.exists(profile_name):
                            logger.info(f"File {profile_name} correctly created")
                            res = parse_perf_results(profile, profile_name)
                            final_results_perf[profile][core].append(res)
                            shutil.move(f"{profile_name}", os.path.join(raw_test_dir, profile_name))
                        else:
                            logger.error(f"Error during the test, file {profile_name} does not exist")

                    logger.debug(f"Let's check if the result file: {stats_file_name} has been created.")

                    if os.path.exists(stats_file_name):
                        logger.info(f"File {stats_file_name} correctly created")
                        mpps = parse_dpdk_results(stats_file_name, duration)
                        final_results_tput[core].append(mpps)
                        shutil.move(f"{stats_file_name}", os.path.join(raw_test_dir, stats_file_name))
                    else:
                        logger.error(f"Error during the test, file {stats_file_name} does not exist")

                    time.sleep(10)
                except Exception as e:
                    logger.critical(e)
                finally:
                    clean_environment(client, version, remote_iface)
                    client.close()
                    exit(1)

    columns_hdr = list()
    for run in range(runs):
        columns_hdr.append(f"run #{run}")

    print(final_results_tput)

    df = pd.DataFrame.from_dict(final_results_tput, orient="index", columns=columns_hdr)
    df.to_csv(output_filename, index=True, index_label="Cores")
    shutil.move(f"{output_filename}", os.path.join(out_dir, output_filename))

    if len(profiles) > 0 and args.profiles is not None:
        perf_file_name= os.path.splitext(output_filename)[0] + f".perf.yaml"
        with open(perf_file_name, 'w') as outfile:
            yaml.dump(final_results_perf, outfile, default_flow_style=False)
        shutil.move(f"{perf_file_name}", os.path.join(out_dir, perf_file_name))

if __name__ == '__main__':
    main()