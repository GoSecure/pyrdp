#!/bin/bash -x

if [[ `cat $@ | jq -e ".info | length"` -lt 4 ]]; then
  echo "JSON conversion failed: info structure too small"
  exit 1
fi

if [[ `cat $@ | jq -e ".events | length"` -ne 25 ]]; then
  echo "JSON conversion failed: not enough events"
  exit 2
fi
