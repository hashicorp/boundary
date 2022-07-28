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

# cannot currently boundary connect ssh -- [args] <cmd> because port and host key are appended
retry 10 ${BOUNDARY_PATH}/boundary connect -target-id=${TARGET_ID} -exec /usr/bin/ssh -- -i ${SSH_KEY_PATH} -l ${SSH_USER} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p {{boundary.port}} {{boundary.ip}} hostname -I
