#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
KERNEL_DOWNLOAD_SCRIPT=$DIR/get-verified-tarball.sh
BPFTOOL_VERSION=5.13

function install_linux_bpftool {
  echo -e "${COLOR_GREEN} Installing Linux bpftool v${BPFTOOL_VERSION} ${COLOR_OFF}"

  # Let's first check if perf is available
  local bpftool_check1=$(command -v bpftool &> /dev/null; echo $?)
  local bpftool_check2=$($SUDO bpftool --help &> /dev/null; echo $?)

  if [ $bpftool_check1 -ne 0 ] || [ $bpftool_check2 -ne 0 ]; then
    echo "bpftool not found"
  else
    echo -e "${COLOR_GREEN} Linux bpftool is already installed ${COLOR_OFF}"
    return
  fi

  sudo rm -rf "${DIR}/deps"

  # If we reach this point, we need to install perf manually
  # Let's start by downloading the kernel
  chmod +x ${KERNEL_DOWNLOAD_SCRIPT}
  ${KERNEL_DOWNLOAD_SCRIPT} ${BPFTOOL_VERSION}

  if [ $? -ne 0 ]; then
    echo -e "${COLOR_RED} Unable to install Linux bpftool v${BPFTOOL_VERSION} ${COLOR_OFF}"
    echo -e "${COLOR_RED} You can try to install it manually${COLOR_OFF}"
    return
  fi

  pushd .
  cd $DIR/deps/linux/tools/bpf/bpftool
  make -j "$(getconf _NPROCESSORS_ONLN)"
  $SUDO make install
  popd

  echo -e "${COLOR_GREEN} Linux bpftool installed. ${COLOR_OFF}"
}

[ -z ${SUDO+x} ] && SUDO='sudo'

$SUDO apt update
PACKAGES=""
PACKAGES+=" build-essential cmake linux-headers-$(uname -r) libelf-dev zlibc libssl-dev libbfd-dev libpcap-dev libcap-dev"
PACKAGES+=" clang-12 clang-tools-12 clang-format-12 llvm llvm-12 llvm-12-dev llvm-12-tools llvm-12-runtime g++-multilib"
PACKAGES+=" pkg-config net-tools bash tcpreplay gnupg gnupg2 gpgv2 curl flex bison" # utility libraries
PACKAGES+=" libnl-3-dev clang" 

$SUDO bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -yq $PACKAGES"


pushd .
cd ${DIR}

set +e
install_linux_bpftool

popd