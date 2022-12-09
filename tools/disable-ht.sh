#!/bin/bash
typeset -i core_id
typeset -i sibling_id
typeset -i state

if [[ $# -ne 1 ]]; then
    echo 'One argument required.'
    echo '1 to turn off hyper-threading'
    echo '0 to turn hyper-threading back on'
    exit 1
fi

for i in /sys/devices/system/cpu/cpu[0-9]*; do
  core_id="${i##*cpu}"
  sibling_id="-1"

  if [ -f ${i}/topology/thread_siblings_list ]; then
    sibling_id="$(cut -d',' -f1 ${i}/topology/thread_siblings_list)"
  fi

  if [ $core_id -ne $sibling_id ]; then
    state="$(<${i}/online)"
    echo -n "$((1-$1))" > "${i}/online"
    echo "switched ${i}/online to $((1-$1))"
  fi
done

exit 0