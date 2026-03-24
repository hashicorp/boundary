# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

function connect_nc() {
  local id=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  echo "SSH-2.0-Test" | boundary connect -exec nc -target-id $id -- -v -w 5 {{boundary.ip}} {{boundary.port}}
}

function connect_alias() {
  local alias=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  echo "SSH-2.0-Test" | boundary connect $alias -exec nc -- -v -w 5 {{boundary.ip}} {{boundary.port}}
}

function connect_alias_with_host_id() {
  local alias=$1
  local hostid=$2
  # Note: When this command returns, the session immediately goes into a "canceling" state
  echo "SSH-2.0-Test" | boundary connect $alias -host-id $hostid -exec nc -- -v -w 5 {{boundary.ip}} {{boundary.port}}
}
