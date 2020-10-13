#!/usr/bin/env bats

load _auth
load _host_catalogs
load _helpers

export NEW_HOST_CATALOG='test'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/hosts-catalogs: can create $NEW_HOST_CATALOG host catalog in default project scope" {
	run create_host_catalog $NEW_HOST_CATALOG $DEFAULT_P_ID
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/hosts: can not create already created $NEW_HOST_CATALOG host catalog in default project scope" {
	run create_host_catalog $NEW_HOST_CATALOG
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/hosts: can read $NEW_HOST_CATALOG host catalog in default project scope" {
  local hid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
	run read_host_catalog $hid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/host: can delete $NEW_HOST_CATALOG host in default project scope" {
  local hid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
  run delete_host_catalog $hid 
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/host: can not delete already deleted $NEW_HOST_CATALOG host in default project scope" {
  local hid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
  run delete_host_catalog $hid 
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/hosts: can not read deleted $NEW_HOST_CATALOG host in default project scope" {
  local hid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
	run read_host_catalog $hid
  echo "$output"
	[ "$status" -eq 1 ]
}
