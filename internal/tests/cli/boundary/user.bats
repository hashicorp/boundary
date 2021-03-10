#!/usr/bin/env bats

load _accounts
load _auth
load _users
load _helpers

export NEW_USER='test'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/users: can add $NEW_USER user" {
	run create_user $NEW_USER
	[ "$status" -eq 0 ]
}

@test "boundary/users: can not add already created $NEW_USER user" {
	run create_user $NEW_USER
	[ "$status" -eq 1 ]
}

@test "boundary/users: can read $NEW_USER user" {
  local uid=$(user_id $NEW_USER)
	run read_user $uid
	[ "$status" -eq 0 ]
}

@test "boundary/users: the $NEW_USER user contains default authorized-actions" {
  local uid=$(user_id $NEW_USER)
  local out=$(read_user $uid)

	run has_default_user_actions "$out" 
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/account/password: can add $NEW_USER account" {
	run create_account $NEW_USER
	[ "$status" -eq 0 ]
}

@test "boundary/account/password: can not add already created $NEW_USER account" {
	run create_account $NEW_USER
	[ "$status" -eq 1 ]
}

@test "boundary/account/password: can read created $NEW_USER account" {
  local aid=$(account_id $NEW_USER)
	run read_account $aid
	[ "$status" -eq 0 ]
}

@test "boundary/user/account-add: can associate $NEW_USER account with $NEW_USER user" {	
  local uid=$(user_id $NEW_USER)
  local aid=$(account_id $NEW_USER)
  run assoc_user_acct $aid $uid
  [ "$status" -eq 0 ]
}

@test "boundary/login: can login as $NEW_USER user" {
  run login $NEW_USER
  [ "$status" -eq 0 ]
}

@test "boundary/user: can delete $NEW_USER user" {
  login $DEFAULT_LOGIN
  local uid=$(user_id $NEW_USER)
  run delete_user $uid 
  [ "$status" -eq 0 ]
}

@test "boundary/users: can not read deleted $NEW_USER user" {
  local uid=$(user_id $NEW_USER)
	run read_user $uid
	[ "$status" -eq 1 ]
}

@test "boundary/account/password: can delete $NEW_USER account" {
  local aid=$(account_id $NEW_USER)
  run delete_account $aid 
  [ "$status" -eq 0 ]
}