#!/bin/bash

function atoi {
  #Returns the integer representation of an IP arg, passed in ascii dotted-decimal notation (x.x.x.x)
  IP=$1
  IPNUM=0
  for ((i = 0; i < 4; ++i)); do
    ((IPNUM += ${IP%%.*} * $((256 ** $((3 - ${i}))))))
    IP=${IP#*.}
  done
  echo $IPNUM
}

function itoa {
  #returns the dotted-decimal ascii form of an IP arg passed in integer format
  echo -n $(($(($(($((${1} / 256)) / 256)) / 256)) % 256)).
  echo -n $(($(($((${1} / 256)) / 256)) % 256)).
  echo -n $(($((${1} / 256)) % 256)).
  echo $((${1} % 256))
}

function signed_to_unsigned {
  local input=$1
  local output
  if [[ $input -lt "0" ]]; then
    output=$((4294967296 + $input))
  else
    output=$input
  fi
  return $output
}
