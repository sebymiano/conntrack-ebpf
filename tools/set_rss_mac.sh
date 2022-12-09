#!/bin/bash
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

ALL_CORES=(1 3 5 7 9 11 13 15 17 19)

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "${DIR}"/helper_functions.sh

if [ $# -ne 3 ]; then
    echo -e "${COLOR_RED} You should provide the interface name as 1st parameter ${COLOR_OFF}"
    echo -e "${COLOR_RED} You should provide the number of cores as 2nd parameter ${COLOR_OFF}"
    echo -e "${COLOR_RED} You should provide the first MAC as 3rd parameter ${COLOR_OFF}"
    exit 1
fi

sudo ethtool -K $1 ntuple on

res=$(sudo ethtool -k $1 | grep "ntuple-filters: on")
if [ -z "$res" ]; then
  echo -e "${COLOR_YELLOW}Warning: The script sets the rules to perform the single core tests${COLOR_OFF}"
  echo -e "${COLOR_YELLOW}The interface $1 does not support it. Results may be unpredictable${COLOR_OFF}"
  exit 0
fi

iface=$1
cores=$2
mac_address=$3

core=0

sudo ethtool --features $1 ntuple off
sudo ethtool --features $1 ntuple on

# Most of the times, disabling ntuple deletes also the entries
# However, this does not work everytime. Let's delete them manually

for i in {1000..2000}; do
  sudo ethtool -N ${iface} delete $i > /dev/null 2>&1
done

while [ "$core" -lt "$cores" ]
do
  if [ "$core" -ne "0" ]; then
    mac=$(echo $mac_address | tr -d ':')
    macadd=$(( 0x$mac + 1 ))
    macnew=$(printf "%012x" $macadd | sed 's/../&:/g;s/:$//')
  else
    macnew=$mac_address
  fi

  set -x
  sudo ethtool -N ${iface} flow-type ether dst ${macnew} action ${ALL_CORES[$core]}
  set +x

  let "core++"
done

exit 0