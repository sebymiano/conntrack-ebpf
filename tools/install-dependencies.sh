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
  mkdir -p "${DIR}/deps"

  pushd .
  cd "${DIR}/deps"
  git clone --recurse-submodules https://github.com/libbpf/bpftool.git

  if [ $? -ne 0 ]; then
    echo -e "${COLOR_RED} Unable to install Linux bpftool v${BPFTOOL_VERSION} ${COLOR_OFF}"
    echo -e "${COLOR_RED} You can try to install it manually${COLOR_OFF}"
    return
  fi

  cd bpftool/src
  make -j "$(getconf _NPROCESSORS_ONLN)"
  $SUDO make install
  popd

  echo -e "${COLOR_GREEN} Linux bpftool installed. ${COLOR_OFF}"
}

[ -z ${SUDO+x} ] && SUDO='sudo'

# check which ubuntu version we are running
UBUNTU_VERSION=$(lsb_release -rs)


$SUDO apt update
PACKAGES=""
PACKAGES+=" build-essential cmake linux-headers-$(uname -r) libelf-dev libssl-dev libbfd-dev libpcap-dev libcap-dev g++-multilib"
PACKAGES+=" pkg-config net-tools bash tcpreplay gnupg gnupg2 gpgv2 curl flex bison" # utility libraries
PACKAGES+=" libnl-3-dev clang python3-pip gnupg2" 

# if Ubuntu is 20.04, we need to install different llvm version
if [[ "${UBUNTU_VERSION}" == "20.04" ]]; then
  echo -e "${COLOR_GREEN} Installing LLVM 18 ${COLOR_OFF}"
  $SUDO bash -c "wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -"
  $SUDO bash -c "echo 'deb http://apt.llvm.org/focal/ llvm-toolchain-focal main' >> /etc/apt/sources.list"
  $SUDO bash -c "echo 'deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal main' >> /etc/apt/sources.list"
  PACKAGES+=" clang-18 clang-tools-18 clang-format-18 llvm-18 llvm-18-dev llvm-18-tools llvm-18-runtime"
elif [[ "${UBUNTU_VERSION}" == "22.04" ]]; then
  echo -e "${COLOR_GREEN} Installing LLVM 18 ${COLOR_OFF}"
  $SUDO bash -c "wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -"
  $SUDO bash -c "echo 'deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy main' >> /etc/apt/sources.list"
  $SUDO bash -c "echo 'deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy main' >> /etc/apt/sources.list"
  PACKAGES+=" clang-18 clang-tools-18 clang-format-18 llvm-18 llvm-18-dev llvm-18-tools llvm-18-runtime"
else
  PACKAGES+=" clang-12 clang-tools-12 clang-format-12 llvm llvm-12 llvm-12-dev llvm-12-tools llvm-12-runtime "
fi

$SUDO apt update
$SUDO bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -yq $PACKAGES"


CURRENT_UBUNTU_VERSION=$(lsb_release -rs)
if [[ "${CURRENT_UBUNTU_VERSION}" == "20.04" ]]; then
  $SUDO bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -yq zlibc"
fi

if [[ "${CURRENT_UBUNTU_VERSION}" == "22.04" ]]; then
  pushd
  cd /usr/lib/x86_64-linux-gnu/
  sudo ln -s -f libc.a liblibc.a
  popd
fi

pushd .
cd ${DIR}

set +e
install_linux_bpftool

sudo python3 -m pip install -r ${DIR}/python_scripts/requirements.txt --user

popd