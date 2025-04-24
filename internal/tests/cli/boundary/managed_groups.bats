#!/usr/bin/env bats

load _auth
load _auth_methods
load _helpers
load _managed_groups

export NEW_MANAGED_GROUP='test_managed_group'
export NEW_GROUP_NAMES='test_group_names'

@test "boundary/managed_group: log in as default user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/managed_group: can create a managed group" {
  local amid=$(get_default_ldap_auth_method_id)
  run create_ldap_managed_group $amid $NEW_MANAGED_GROUP $NEW_GROUP_NAMES
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/managed_group: can update a managed group" {
  local amid=$(get_default_ldap_auth_method_id)
  local mgid=$(managed_group_id $amid $NEW_MANAGED_GROUP)
  run update_ldap_managed_group $amid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/managed_group: can delete a managed group" {
  local amid=$(get_default_ldap_auth_method_id)
  local mgid=$(managed_group_id $amid $NEW_MANAGED_GROUP)
  run delete_managed_group $mgid
  echo "$output"
  [ "$status" -eq 0 ]
}
