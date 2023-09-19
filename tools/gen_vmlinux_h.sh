#/bin/sh

# Check if there is a argument passed to this script, if yes, use it as the path to bpftool
if [ $# -eq 0 ]
  then
    bpftool_exec=bpftool
  else
    bpftool_exec=$1
fi

$bpftool_exec btf dump file ${2:-/sys/kernel/btf/vmlinux} format c > $(dirname "$0")/../vmlinux/vmlinux.h
