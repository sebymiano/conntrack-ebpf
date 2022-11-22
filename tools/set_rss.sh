#!/bin/bash
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

ALL_CORES=(1 3 5 7 9 11 13 15 17 19)

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "${DIR}"/helper_functions.sh

if [ $# -ne 3 ]; then
    echo -e "${COLOR_RED} You should provide the name of the interface as 1st parameter ${COLOR_OFF}"
    echo -e "${COLOR_RED} You should provide the IP address (IPadd/sub) as 2nd parameter ${COLOR_OFF}"
    echo -e "${COLOR_RED} You should provide the number of cores as 3rd parameter ${COLOR_OFF}"
    exit 1
fi

if ! [ -x "$(command -v ipcalc)" ]; then
    echo "${COLOR_YELLOW} Ipcalc is not installed. ${COLOR_OFF}"
    sudo apt update && sudo apt install -y ipcalc
fi

sudo ethtool -K $1 ntuple on

res=$(sudo ethtool -k $1 | grep "ntuple-filters: on")
if [ -z "$res" ]; then
  echo -e "${COLOR_YELLOW}Warning: The script sets the rules to perform the single core tests${COLOR_OFF}"
  echo -e "${COLOR_YELLOW}The interface $1 does not support it. Results may be unpredictable${COLOR_OFF}"
  exit 0
fi

iface=$1
subnet=$2
number_of_splits=$3
IPsPerNet=`ipcalc -n -b $subnet |grep "Hosts/Net" | awk '{print $2}'`
#echo $IPsPerNet
core=0

sudo ethtool --features $1 ntuple off
sudo ethtool --features $1 ntuple on

while [ "$number_of_splits" -gt "0" ]
do
  let "HostsPerNet=($IPsPerNet-2)/$number_of_splits"
  usednetwork=$(ipcalc -n -b $subnet -s $HostsPerNet| grep "Used"| awk '{print $3}')
  subnet=$(ipcalc -n -b $subnet -s $HostsPerNet| tail -n1)
  IPsPerNet=$(ipcalc -n -b $subnet |grep "Hosts/Net" | awk '{print $2}')
  network_address=$(ipcalc -n -b $usednetwork | grep "Address" | awk '{print $2}')
  wildcard=$(ipcalc -n -b $usednetwork | grep "Wildcard" | awk '{print $2}')

  set -x
  sudo ethtool -N ${iface} flow-type tcp4 src-ip ${network_address} m ${wildcard} action ${ALL_CORES[$core]}
  set +x

  let "number_of_splits--"
  let "core++"
done