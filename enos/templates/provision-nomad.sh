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

# Create a unique, non-privileged system user to run Nomad
getent passwd nomad \
|| sudo useradd --system --home /etc/nomad.d --shell /bin/false nomad

# Create a data directory for Nomad
sudo mkdir --parents /opt/nomad
sudo chown nomad /opt/nomad 

# Start the Nomad service
sudo systemctl enable nomad
sudo systemctl start nomad

# Check the Nomad service
retry 10 nomad server members \
| grep -c alive \
| grep -s $INSTANCE_COUNT
