# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

function connect_nc() {
  local id=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  echo "foo" | boundary connect -exec nc -target-id $id -- {{boundary.ip}} {{boundary.port}}
}

function connect_alias() {
  local alias=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  echo "foo" | boundary connect $alias -exec nc -- {{boundary.ip}} {{boundary.port}}
}

function connect_alias_with_host_id() {
  local alias=$1
  local hostid=$2
  # Note: When this command returns, the session immediately goes into a "canceling" state
  echo "foo" | boundary connect $alias -host-id $hostid -exec nc -- {{boundary.ip}} {{boundary.port}}
}