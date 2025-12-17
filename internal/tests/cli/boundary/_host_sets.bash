# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

load _authorized_actions

function create_host_set() {
  local hcid=$1
  local name=$2
  boundary host-sets create static \
    -host-catalog-id $hcid \
    -name $name \
    -description 'test group'
}

function read_host_set() {
  boundary host-sets read -id $1 -format json
}

function delete_host_set() {
  boundary host-sets delete -id $1 -format json
}

function list_host_sets() {
  boundary host-sets list -host-catalog-id $1 -format json
}

function assoc_host_set_host() {
  boundary host-sets add-hosts -host $1 -id $2
}

function host_set_id() {
  local name=$1
  local hcid=$2
  strip $(list_host_sets $hcid | jq -c ".items[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}

function host_set_host_ids() {
  local id=$1
  ids=$(read_host_set $id | jq '.item["host_ids"]')
  echo "ids $ids"
}

function host_set_has_host_id() {
  local hid=$1
  local hsid=$2
  ids=$(host_set_host_ids $hsid)
  echo "ids $ids hid $hid hsid $hsid"
  for id in $ids; do
    if [ $(strip "$id") == "$hid" ]; then
      return 0 
    fi
  done
  return 1 
}

function has_default_host_set_actions() {
  local out=$1
  local actions=('read' 'update' 'delete' 'add-hosts' 'set-hosts' 'remove-hosts')

  for action in ${actions[@]}; do
    $(has_authorized_action "$out" "$action") || {
      echo "failed to find $action action in output: $out"
      return 1 
    } 
  done
}
