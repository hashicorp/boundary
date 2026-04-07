# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

function connect_nc() {
  local id=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  boundary connect -exec nc -target-id $id -- -w 5 -v {{boundary.ip}} 12345 < /dev/null
}

function connect_alias() {
  local alias=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  boundary connect $alias -exec nc -- -w 5 -v {{boundary.ip}} {{boundary.port}} < /dev/null
}

function connect_alias_with_host_id() {
  local alias=$1
  local hostid=$2
  # Note: When this command returns, the session immediately goes into a "canceling" state
  boundary connect $alias -host-id $hostid -exec nc -- -w 5 -v {{boundary.ip}} {{boundary.port}} < /dev/null
}
