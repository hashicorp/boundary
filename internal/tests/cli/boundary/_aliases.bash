# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

load _authorized_actions

function create_target_alias() {
  local value=$1
  local destid=$2
  boundary aliases create target \
    -value $value \
    -destination-id $destid \
    -format json
}

function create_target_alias_with_host_id() {
  local value=$1
  local destid=$2
  local hostid=$3
  boundary aliases create target \
    -value $value \
    -destination-id $destid \
    -authorize-session-host-id $hostid \
    -format json
}

function read_alias(){
  boundary aliases read -id $1 -format json
}

function delete_alias(){
  boundary aliases delete -id $1 -format json
}

function list_alias(){
  boundary aliases list -format json
}

function update_target_alias_value(){
    local aid=$1
    local value=$2
    boundary aliases update target \
      -id $aid \
      -value $value \
      -format json
}

function update_target_alias_host_id(){
    local aid=$1
    local hostid=$2
    boundary aliases update target \
      -id $aid \
      -authorize-session-host-id $hostid \
      -format json
}

function update_target_alias_remove_destination_id(){
    local aid=$1
    boundary aliases update target \
      -id $aid \
      -destination-id null \
      -format json
}

function update_target_alias_destination_id(){
    local aid=$1
    local destid=$2
    boundary aliases update target \
      -id $aid \
      -destination-id $destid \
      -format json
}

function alias_id_from_target_alias(){
    local alias=$1
    strip $(list_alias | jq -c ".items[] | select(.value | contains(\"$alias\")) | .[\"id\"]")
}

function host_id_from_alias_id(){
  local aid=$1
  strip $(read_alias $aid | jq -c ".item | .attributes | .authorize_session_arguments | .host_id")
}