#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

set -eux

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$NEW_DIR" ]] && fail "NEW_DIR env variable has not been set"
[[ -z "$SERVICE_USER" ]] && fail "SERVICE_USER env variable has not been set"

function retry {
  local retries=$1
  shift
  local count=0

  until "$@"; do
    exit=$?
    wait=10
    count=$((count + 1))

    if [ "$count" -lt "$retries" ]; then
      sleep "$wait"
    else
      return "$exit"
    fi
  done

  return 0
}

retry 7 id -a "$SERVICE_USER"

sudo mkdir -p "$NEW_DIR"
sudo chown -R "$SERVICE_USER":"$SERVICE_USER" "$NEW_DIR"
