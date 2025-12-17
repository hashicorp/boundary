# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

load _authorized_actions

function list_sessions_include_terminated() {
  boundary sessions list -scope-id $1 -include-terminated -format json
}

function count_sessions_include_terminated() {
  list_sessions_include_terminated $1 | jq '.items | length'
}

function cancel_session() {
  boundary sessions cancel -id $1
}

function read_session() {
  boundary sessions read -id $1
}
