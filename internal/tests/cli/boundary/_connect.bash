# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

function connect_nc() {
  local id=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  run_with_cli_timeout boundary connect -exec nc -target-id $id -- -z -w 3 -v {{boundary.ip}} {{boundary.port}}
}

function connect_alias() {
  local alias=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  run_with_cli_timeout boundary connect $alias -exec nc -- -z -w 3 -v {{boundary.ip}} {{boundary.port}}
}

function connect_alias_with_host_id() {
  local alias=$1
  local hostid=$2
  # Note: When this command returns, the session immediately goes into a "canceling" state
  run_with_cli_timeout boundary connect $alias -host-id $hostid -exec nc -- -z -w 3 -v {{boundary.ip}} {{boundary.port}}
}
