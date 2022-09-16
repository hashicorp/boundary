#!/bin/bash
set -e

function retry {
  local retries=$1
  shift
  local count=0

  until "$@"; do
    exit=$?
    wait=$((2 ** count))
    count=$((count + 1))

    if [ "$count" -lt "$retries" ]; then
      sleep "$wait"
    else
      return "$exit"
    fi
  done

  return 0
}

retry 10 ${BOUNDARY_PATH}/boundary connect ssh -target-id=${TARGET_ID}
