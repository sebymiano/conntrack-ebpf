#!/bin/bash
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ $# -ne 1 ]; then
    echo -e "${COLOR_RED} You should provide the interface name as 1st parameter ${COLOR_OFF}"
    exit 1
fi

iface=$1

for i in {1000..2000}; do
  sudo ethtool -N ${iface} delete $i > /dev/null 2>&1
done

sudo ethtool --features ${iface} ntuple off