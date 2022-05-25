#!/usr/bin/env bats

load _auth
load _helpers
load _credential_stores
load _credentials

export NEW_STORE='credentials-test-store'
export NEW_CREDENTIAL='test'

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

@test "boundary/credentials: can create $NEW_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
	run create_user_password_credential $NEW_STORE $csid 'username' 'password'
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/credentials: can not create already created $NEW_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
	run create_user_password_credential $NEW_STORE $csid 'username' 'password'
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/credentials: can read $NEW_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
	run read_credential $cid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/credentials: can delete $NEW_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run delete_credential $cid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can not read deleted $NEW_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
	run read_credential $cid
  echo "$output"
	[ "$status" -eq 1 ]
}
