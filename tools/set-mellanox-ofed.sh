#!/bin/bash

wget http://content.mellanox.com/ofed/MLNX_OFED-5.8-1.1.2.1/MLNX_OFED_LINUX-5.8-1.1.2.1-ubuntu22.04-x86_64.tgz
tar -xvzf MLNX_OFED_LINUX-5.8-1.1.2.1-ubuntu22.04-x86_64.tgz
cd MLNX_OFED_LINUX-5.8-1.1.2.1-ubuntu22.04-x86_64
sudo ./mlnxofedinstall --with-mft --with-mstflint --dpdk --upstream-libs --add-kernel-support