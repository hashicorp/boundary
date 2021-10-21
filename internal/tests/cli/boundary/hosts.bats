#!/usr/bin/env bats

load _auth
load _hosts
load _helpers

export NEW_HOST='test'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/hosts: can create $NEW_HOST host in default host catalog" {
	run create_host $NEW_HOST $DEFAULT_HOST_CATALOG
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/hosts: can not add already created $NEW_HOST host in default host catalog" {
	run create_host $NEW_HOST $DEFAULT_HOST_CATALOG
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/hosts: can read $NEW_HOST host" {
  local hid=$(host_id $NEW_HOST $DEFAULT_HOST_CATALOG)
	run read_host $hid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/hosts: the $NEW_HOST host contains default authorized-actions" {
  local hid=$(host_id $NEW_HOST $DEFAULT_HOST_CATALOG)
  local out=$(read_host $hid)

	run has_default_host_actions "$out" 
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/host: can delete $NEW_HOST host" {
  local hid=$(host_id $NEW_HOST $DEFAULT_HOST_CATALOG)
  run delete_host $hid 
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/hosts: can not read deleted $NEW_HOST host" {
  local hid=$(host_id $NEW_HOST $DEFAULT_HOST_CATALOG)
	run read_host $hid
  echo "$output"
	[ "$status" -eq 1 ]
}
