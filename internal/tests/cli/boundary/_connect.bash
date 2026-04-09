# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

function connect_nc() {
  local id=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  # Capture output and check for success message since nc may return non-zero on pipe close
  local output
  output=$(echo "SSH-2.0-Test" | boundary connect -exec nc -target-id $id -- -v -w 5 {{boundary.ip}} {{boundary.port}} 2>&1)
  local status=$?
  echo "$output"

  # If connection succeeded, return 0 regardless of nc's exit status
  if echo "$output" | grep -q "succeeded"; then
    return 0
  fi
  return $status
}

function connect_alias() {
  local alias=$1
  # Note: When this command returns, the session immediately goes into a "canceling" state
  # Capture output and check for success message since nc may return non-zero on pipe close
  local output
  output=$(echo "SSH-2.0-Test" | boundary connect $alias -exec nc -- -v -w 5 {{boundary.ip}} {{boundary.port}} 2>&1)
  local status=$?
  echo "$output"

  # If connection succeeded, return 0 regardless of nc's exit status
  if echo "$output" | grep -q "succeeded"; then
    return 0
  fi
  return $status
}

function connect_alias_with_host_id() {
  local alias=$1
  local hostid=$2
  # Note: When this command returns, the session immediately goes into a "canceling" state
  # Capture output and check for success message since nc may return non-zero on pipe close
  local output
  output=$(echo "SSH-2.0-Test" | boundary connect $alias -host-id $hostid -exec nc -- -v -w 5 {{boundary.ip}} {{boundary.port}} 2>&1)
  local status=$?
  echo "$output"

  # If connection succeeded, return 0 regardless of nc's exit status
  if echo "$output" | grep -q "succeeded"; then
    return 0
  fi
  return $status
}
