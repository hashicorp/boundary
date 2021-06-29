#!/usr/bin/env bats

load _auth
load _credential_stores
load _helpers

export NEW_CREDENTIAL_STORE='test'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can create $NEW_CREDENTIAL_STORE credential store in default project scope" {
	run create_credential_store $NEW_CREDENTIAL_STORE $DEFAULT_P_ID
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can not create already created $NEW_CREDENTIAL_STORE credential store in default project scope" {
	run create_credential_store $NEW_CREDENTIAL_STORE
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/credential-stores: can read $NEW_CREDENTIAL_STORE credential store in default project scope" {
  local hid=$(credential_store_id $NEW_CREDENTIAL_STORE $DEFAULT_P_ID)
	run read_credential_store $hid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can not read deleted $NEW_CREDENTIAL_STORE host in default project scope" {
  local hid=$(credential_store_id $NEW_CREDENTIAL_STORE $DEFAULT_P_ID)
	run read_credential_store $hid
  echo "$output"
	[ "$status" -eq 1 ]
}
