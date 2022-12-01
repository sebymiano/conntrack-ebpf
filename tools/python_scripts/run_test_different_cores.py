import argparse
import yaml
import sys
import os
import paramiko
import time
import subprocess

CONFIG_file_default = f"{sys.path[0]}/config_test.yaml"

def kill_tmux_session(client, session_name):
    _, ssh_stdout, _ = client.exec_command(f"tmux kill-session -t {session_name}")
    return ssh_stdout.channel.recv_exit_status()

def init_remote_client(client, remote_conntrack_path, remote_iface, core, version, duration):
    _, ssh_stdout, _ = client.exec_command(f"sudo -S ethtool -L {remote_iface} combined {core}")
    if ssh_stdout.channel.recv_exit_status() == 0:
        print(f"Changed NIC queues to {core}")
    else:
        raise Exception("Error while executing ethtool command")

    # Adding 60 seconds to make sure the system will setup everything before closing the test
    new_duration = duration + 60
    if version == "v1":
        conntrack_bin = f"{remote_conntrack_path}/src/conntrack"
        conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -q -r -d {new_duration}"
    else:
        conntrack_bin = f"{remote_conntrack_path}/src/conntrack_v2"
        conntrack_cmd = f"{conntrack_bin} -1 {remote_iface} -p -q -r -n {core} -d {new_duration}"

    _, ssh_stdout, _ = client.exec_command(f"tmux new-session -d -s conntrack 'sudo {conntrack_cmd}'")

    print("Command sent to remote server, let's wait until it starts")
    print(f"Cmd: {conntrack_cmd}")
    time.sleep(30)
    
    _, ssh_stdout, _ = client.exec_command(f"pgrep -l {conntrack_bin}")
    cmd_output = ssh_stdout.readlines()
    if not cmd_output:
        raise Exception("Conntrack command not executed successfully")
    else:
        print("Conntrack command executed successfully")


    print("Let's now set the core affinity")
    _, ssh_stdout, _ = client.exec_command(f"sudo {remote_conntrack_path}/tools/set_irq_affinity.sh local {remote_iface}")
    if ssh_stdout.channel.recv_exit_status() == 0:
        print(f"Set correct core affinity")
    else:
        kill_tmux_session(client, "conntrack")
        raise Exception("Error while setting core affinity")   


def main():
    desc = """Run test for conntrack_bpf with different number of cores"""
    
    parser = argparse.ArgumentParser(description = desc)
    parser.add_argument("-c", "--config-file", type=str, default=CONFIG_file_default, help="The YAML config file")
    parser.add_argument("-o", '--out', type=str, required = True, help='Output file name')
    parser.add_argument("-v", '--version', default='v1', const='v1', nargs='?', choices=['v1', 'v2'], help='v1 is for shared state, v2 is for local state')
    parser.add_argument("-n", "--num-cores", type=int, required = True, help="Number of cores")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration of the test")

    args = parser.parse_args()

    if (os.path.isfile(args.out)):
        print('"{}" already exists, refusing to overwrite.'.format(args.out))
        sys.exit(-1)

    with open(args.config_file, "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit(-1)

    version = args.version
    num_cores = args.num_cores
    duration = args.duration

    remote_host = config["remote_host"]
    remote_user = config["remote_user"]
    remote_conntrack_path = config["remote_conntrack_path"]
    remote_iface = config["remote_iface"]
    local_iface_pci_id = config["local_iface_pci_id"]
    local_numa_core = config["local_numa_core"]

    if ("local_private_key" not in config) or (not config["local_private_key"]):
        print("The YAML file does not provide any private key.")
        default_path = os.path.join(os.environ["HOME"], ".ssh", "id_rsa")
        print(f"I'll use the default key from: {default_path}")
        local_private_key = default_path
    else:
        local_private_key = config["local_private_key"]

    for core in range(1, num_cores + 1):
        pcap_path_found = False
        pcap_path = ""

        for pcap in config["local_pcaps"]:
            if int(pcap["core"]) == core:
                pcap_path = pcap["path"]
                pcap_path_found = True
            
        if not pcap_path_found:
            print(f"No pcap path found for core: {core}")
            continue

        try:
            client = paramiko.SSHClient()
            k = paramiko.RSAKey.from_private_key_file(local_private_key)

            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                client.connect(hostname=remote_host, username=remote_user, pkey=k)
            except Exception as e:
                print("Failed to connect. Exit!")
                print("*** Caught exception: %s: %s" % (e.__class__, e))
                sys.exit(1)


            init_remote_client(client, remote_conntrack_path, remote_iface, core, version, duration)
            stats_file_name = f"result_{version}_core{core}.csv"
            pktgen_cmd = f"sudo dpdk-replay --nbruns 100000000 --numacore {local_numa_core} \
                           --timeout ${duration} --stats {local_iface_pci_id} \
                           --stats-name {stats_file_name} --write-csv {pcap_path}"

            generator_run = subprocess.run(pktgen_cmd.split())
            print(f"The exit code was: {generator_run.returncode}")

            print(f"Let's check if the result file: {stats_file_name} has been created.")

            if os.path.exists(stats_file_name):
                print(f"File {stats_file_name} correctly created")
            else:
                print(f"Error during the test, file {stats_file_name} does not exist")
        finally:
            if client.active:
                client.close()

if __name__ == '__main__':
    main()