#!/usr/bin/env bash

set -e pipefail

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


# Get us some docker
if [ -f /etc/debian_version ]; then
  # Make sure cloud-init is not modifying our sources list while we're trying
  # to install.
  retry 7 grep ec2 /etc/apt/sources.list
  retry 5 sudo apt update
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo sh get-docker.sh
fi
