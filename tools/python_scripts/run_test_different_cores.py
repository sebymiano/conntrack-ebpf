import argparse
import yaml
import sys
import os
import paramiko
import time
import subprocess
import pandas as pd
import numpy as np

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
    if version == "v1":
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

def copy_file_from_remote_host(client, remote_file, local_file):
    logger.debug(f"Copy files from {remote_file} to {local_file}")
    ftp_client=client.open_sftp()
    ftp_client.get(remote_file, local_file)

    client.exec_command(f"sudo rm {remote_file}")

    ftp_client.close()

def init_remote_client(client, remote_conntrack_path, remote_iface, core, version, action, duration, stats_file_name):
    #make sure we start from a clean environment
    clean_environment(client, version, remote_iface)

    _, ssh_stdout, _ = client.exec_command(f"sudo -S ethtool -L {remote_iface} combined {core}")
    if ssh_stdout.channel.recv_exit_status() == 0:
        logger.debug(f"Changed NIC queues to {core}")
    else:
        raise Exception("Error while executing ethtool command")

    logger.info("Let's disable cstates")
    _, ssh_stdout, _ = client.exec_command(f"sudo {remote_conntrack_path}/tools/set_cpu_frequency.sh")
    if ssh_stdout.channel.recv_exit_status() == 0:
        logger.debug(f"Cstates disabled")
    else:
        raise Exception("Error while disabling cstates")   

    # Adding 60 seconds to make sure the system will setup everything before closing the test
    new_duration = duration + 60
    if version == "v1":
        conntrack_bin_name = "conntrack"
        conntrack_bin = f"{remote_conntrack_path}/src/{conntrack_bin_name}"
        if action == "DROP":
            conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -d {new_duration} -o {stats_file_name}"
        else:    
            conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -q -r -d {new_duration}"
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


def parse_dpdk_results(stats_file_name):
    df = pd.read_csv(stats_file_name)
    # Discard 10 elements at beginning and at end
    mpps = round(np.mean(df["RX-packets"][10:-10])/1e6, 2)
    return mpps


def main():
    desc = """Run test for conntrack_bpf with different number of cores"""
    
    parser = argparse.ArgumentParser(description = desc)
    parser.add_argument("-c", "--config-file", type=str, default=CONFIG_file_default, help="The YAML config file")
    parser.add_argument("-o", '--out', type=str, required = True, help='Output file name')
    parser.add_argument("-v", '--version', default='v1', const='v1', nargs='?', choices=['v1', 'v2'], help='v1 is for shared state, v2 is for local state')
    parser.add_argument("-n", "--num-cores", type=int, required = True, help="Max number of cores. The test will start from 1 to this value")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration of the test")
    parser.add_argument("-r", "--runs", type=int, default=5, help="Number of runs for each test")
    parser.add_argument("-a", '--action', default='REDIR', const='REDIR', nargs='?', choices=['REDIR', 'DROP'], help='REDIR is to redirect packets on the same iface, DROP is to drop all pkts')

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

    remote_host = config["remote_host"]
    remote_user = config["remote_user"]
    remote_conntrack_path = config["remote_conntrack_path"]
    remote_iface = config["remote_iface"]
    local_iface_pci_id = config["local_iface_pci_id"]
    local_numa_core = config["local_numa_core"]

    if ("local_private_key" not in config) or (not config["local_private_key"]):
        logger.warning("The YAML file does not provide any private key.")
        default_path = os.path.join(os.environ["HOME"], ".ssh", "id_rsa")
        logger.info(f"I'll use the default key from: {default_path}")
        local_private_key = default_path
    else:
        local_private_key = config["local_private_key"]

    final_results = dict()

    for core in range(1, num_cores + 1):
        final_results[core] = list()
        for run in range(runs):
            pcap_path_found = False
            pcap_path = ""

            for pcap in config["local_pcaps"]:
                if int(pcap["core"]) == core:
                    pcap_path = pcap["path"]
                    pcap_path_found = True
                
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

                stats_file_name = f"result_{version}_core{core}_run{run}.csv"
                init_remote_client(client, remote_conntrack_path, remote_iface, core, version, action, duration, f"{remote_conntrack_path}/src/{stats_file_name}")

                if action == "DROP":
                    pktgen_cmd = (f"sudo dpdk-replay --nbruns 100000000 --numacore {local_numa_core} "
                                  f"--timeout {duration} --stats {local_iface_pci_id} "
                                  f"{pcap_path} {local_iface_pci_id}")
                else:
                    pktgen_cmd = (f"sudo dpdk-replay --nbruns 100000000 --numacore {local_numa_core} "
                                  f"--timeout {duration} --stats {local_iface_pci_id} "
                                  f"--stats-name {stats_file_name} --write-csv {pcap_path} {local_iface_pci_id}")

                logger.debug(f"Executing local pktgen command: {pktgen_cmd}")
                generator_run = subprocess.run(pktgen_cmd.split())
                logger.debug(f"The exit code was: {generator_run.returncode}")

                if action == "DROP":
                    logger.debug("Going to sleep for 60s, waiting for the remote to save results")
                    time.sleep(60)
                    copy_file_from_remote_host(client, f"{remote_conntrack_path}/src/{stats_file_name}", f"{sys.path[0]}/{stats_file_name}")

                logger.debug(f"Let's check if the result file: {stats_file_name} has been created.")

                if os.path.exists(stats_file_name):
                    logger.info(f"File {stats_file_name} correctly created")
                    mpps = parse_dpdk_results(stats_file_name)
                    final_results[core].append(mpps)
                else:
                    logger.error(f"Error during the test, file {stats_file_name} does not exist")

                time.sleep(30)
            finally:
                clean_environment(client, version, remote_iface)
                client.close()

    columns_hdr = list()
    columns_hdr.append("Cores")
    for run in range(runs):
        columns_hdr.append(f"run #{run}")

    df = pd.DataFrame.from_dict(final_results, orient="index", columns=columns_hdr)
    df.to_csv(output_filename)

if __name__ == '__main__':
    main()