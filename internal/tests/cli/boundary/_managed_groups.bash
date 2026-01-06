# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

function create_ldap_managed_group() {
  local amid=$1
  local name=$2
  local gnames=$3
  boundary managed-groups create ldap -auth-method-id $amid -name $name -group-names $gnames -format json
}

function read_managed_group() {
  local mgid=$1
  boundary managed-groups read -id $mgid -format json
}

function list_managed_groups() {
  local amid=$1
  boundary managed-groups list -auth-method-id $amid -format json
}

function update_ldap_managed_group() {
  local $mgid=$1
  boundary managed-groups update ldap -id $mgid -description "TEST"
}

function delete_managed_group() {
  local mgid=$1
  boundary managed-groups delete -id $mgid -format json
}

function managed_group_id() {
  local amid=$1
  local name=$2
  strip $(list_managed_groups $amid | jq -c ".items[] | select(.name != null) | select(.name | contains(\"$name\")) | .[\"id\"]")
}
