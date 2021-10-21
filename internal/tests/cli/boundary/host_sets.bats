#!/usr/bin/env bats

load _auth
load _host_sets
load _helpers

export NEW_HOST_SET='test'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/host-sets: can add $NEW_HOST_SET host set to default host catalog" {
	run create_host_set $DEFAULT_HOST_CATALOG $NEW_HOST_SET
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/host-sets: can not add already created $NEW_HOST_SET host set" {
	run create_host_set $DEFAULT_HOST_CATALOG $NEW_HOST_SET
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/host-sets: can read $NEW_HOST_SET host set" {
  local hsid=$(host_set_id $NEW_HOST_SET $DEFAULT_HOST_CATALOG)
	run read_host_set $hsid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/host-sets: the $NEW_HOST_SET host set contains default authorized-actions" {
  local hsid=$(host_set_id $NEW_HOST_SET $DEFAULT_HOST_CATALOG)
  local out=$(read_host_set $hsid)

	run has_default_host_set_actions "$out" 
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/host-set/add-host: can associate $NEW_HOST_SET host set with default host" {	
  local hsid=$(host_set_id $NEW_HOST_SET $DEFAULT_HOST_CATALOG)
  run assoc_host_set_host $DEFAULT_HOST $hsid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/host-set/add-host: $NEW_HOST_SET host set contains default host" {	
  local hsid=$(host_set_id $NEW_HOST_SET $DEFAULT_HOST_CATALOG)
  run host_set_has_host_id $DEFAULT_HOST $hsid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/host-set: can delete $NEW_HOST_SET host set" {
  local hsid=$(host_set_id $NEW_HOST_SET $DEFAULT_HOST_CATALOG)
  run delete_host_set $hsid 
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/host-set: can not delete already deleted $NEW_HOST_SET host set" {
  local hsid=$(host_set_id $NEW_HOST_SET $DEFAULT_HOST_CATALOG)
  run delete_host_set $hsid 
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/host-sets: can not read deleted $NEW_HOST_SET host set" {
  local hsid=$(host_set_id $NEW_HOST_SET $DEFAULT_HOST_CATALOG)
	run read_host_set $hsid
  echo "$output"
	[ "$status" -eq 1 ]
}
