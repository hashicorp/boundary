# Copyright (c) HashiCorp, Inc.
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