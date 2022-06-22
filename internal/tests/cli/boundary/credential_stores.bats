#!/usr/bin/env bats

load _auth
load _helpers
load _credential_stores

export NEW_STORE='test'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can create $NEW_STORE static store in default project" {
	run create_static_credential_store $NEW_STORE $DEFAULT_P_ID
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can not create already created $NEW_STORE static store" {
	run create_static_credential_store $NEW_STORE $DEFAULT_P_ID
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/credential-stores: can read $NEW_STORE static store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
	run read_credential_store $csid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can delete $NEW_STORE static store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run delete_credential_store $csid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can not read deleted $NEW_STORE static store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
	run read_credential_store $csid
  echo "$output"
	[ "$status" -eq 1 ]
}
