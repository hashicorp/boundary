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

@test "boundary/host-catalogs: can create $NEW_HOST_CATALOG host catalog in default project scope" {
	run create_host_catalog $NEW_HOST_CATALOG $DEFAULT_P_ID
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/host-catalogs: can not create already created $NEW_HOST_CATALOG host catalog in default project scope" {
	run create_host_catalog $NEW_HOST_CATALOG
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/host-catalogs: can read $NEW_HOST_CATALOG host catalog in default project scope" {
  local hid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
	run read_host_catalog $hid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/host-catalogs: the $NEW_HOST_CATALOG host catalog contains default authorized-actions" {
  local hid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
  local out=$(read_host_catalog $hid)

	run has_default_host_catalog_actions "$out" 
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/host-catalogs: can delete $NEW_HOST_CATALOG host in default project scope" {
  local hid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
  run delete_host_catalog $hid 
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/host-catalogs: can not read deleted $NEW_HOST_CATALOG host in default project scope" {
  local hid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
	run read_host_catalog $hid
  echo "$output"
	[ "$status" -eq 1 ]
}
