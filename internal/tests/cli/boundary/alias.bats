#!/usr/bin/env bats

load _auth
load _connect
load _aliases
load _helpers
load _hosts
load _host_sets
load _targets

export ALIAS_VALUE='test'
export UPDATE_ALIAS_VALUE='test.change'
export NEW_HOST="host_for_alias_test"

@test "boundary/login: can login as admin user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user cannot create alias with incorrectly formatted destination id" {
  run create_target_alias $ALIAS_VALUE incorrectly-formatted-destination-id
  [ "$status" -eq 1 ]
}

@test "boundary/alias: admin user cannot create alias with incorrectly formatted host id" {
  run create_target_alias_with_host_id $ALIAS_VALUE $DEFAULT_TARGET incorrectly-formatted-host-id
  [ "$status" -eq 1 ]
}

@test "boundary/alias: admin user can create alias" {
  run create_target_alias $ALIAS_VALUE $DEFAULT_TARGET
  echo $output
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can not create already created alias" {
  run create_target_alias $ALIAS_VALUE $DEFAULT_TARGET
  [ "$status" -eq 1 ]
}

@test "boundary/alias: admin user can list aliases" {
  run list_alias
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can read created alias" {
  local id=$(alias_id_from_target_alias $ALIAS_VALUE)
  run read_alias $id
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can read target using an alias" {
  run read_target $ALIAS_VALUE
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can connect to target using an alias" {
  run connect_alias $ALIAS_VALUE
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can connect passing in a host id" {
  run connect_alias_with_host_id $ALIAS_VALUE $DEFAULT_HOST
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can update alias host id" {
  local id=$(alias_id_from_target_alias $ALIAS_VALUE)
  run update_target_alias_host_id $id $DEFAULT_HOST
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user cannot update alias with incorrectly formatted host id" {
  local id=$(alias_id_from_target_alias $ALIAS_VALUE)
  run update_target_alias_host_id $id incorrectly-formatted-host-id
  [ "$status" -eq 1 ]
}

@test "boundary/alias: admin user cannot update alias with incorrectly formatted destination id" {
  local id=$(alias_id_from_target_alias $ALIAS_VALUE)
  run update_target_alias_destination_id $id incorrectly-formatted-destination-id
  [ "$status" -eq 1 ]
}

@test "boundary/alias: admin user can connect using an alias configured with host id" {
  run connect_alias $ALIAS_VALUE
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can connect using an alias configured with host id passing in same host id" {
  run connect_alias_with_host_id $ALIAS_VALUE $DEFAULT_HOST
  [ "$status" -eq 0 ]
}

@test "boundary/host: admin can create new host" {
  run create_host $NEW_HOST $DEFAULT_HOST_CATALOG
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/host: admin can associate new host to host set" {
  local new_host_id=$(host_id $NEW_HOST $DEFAULT_HOST_CATALOG)
  run assoc_host_set_host $new_host_id $DEFAULT_HOST_SET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user cannot connect using an alias configured with host id passing in different host id" {
  local new_host_id=$(host_id NEW_HOST $DEFAULT_HOST_CATALOG)
  run connect_alias_with_host_id $ALIAS_VALUE $new_host_id
  [ "$status" -eq 1 ]
}

@test "boundary/host: admin can delete new host" {
  local new_host_id=$(host_id $NEW_HOST $DEFAULT_HOST_CATALOG)
  run delete_host $new_host_id 
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can remove destination id and host id will also be cleared out" {
  local id=$(alias_id_from_target_alias $ALIAS_VALUE)
  run update_target_alias_remove_destination_id $id
  local hostid=$(host_id_from_alias_id $id)
  [ ! -z "$hostid" ]
}

@test "boundary/alias: admin user can update alias value" {
  local id=$(alias_id_from_target_alias $ALIAS_VALUE)
  run update_target_alias_value $id $UPDATE_ALIAS_VALUE
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can delete alias" {
  local id=$(alias_id_from_target_alias $UPDATE_ALIAS_VALUE)
  run delete_alias $id
  [ "$status" -eq 0 ]
}

@test "boundary/alias: can login as unpriv user" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/alias: unpriv user cannot list aliases" {
  run list_alias
  [ "$status" -eq 1 ]
}

@test "boundary/alias: unpriv user cannot read aliases" {
  local id=$(alias_id_from_target_alias $ALIAS_VALUE)
  run read_alias $id
  [ "$status" -eq 1 ]
}

@test "boundary/alias: unpriv user cannot create aliases" {
  run create_target_alias bogus $DEFAULT_TARGET
  echo $output
  [ "$status" -eq 1 ]
}