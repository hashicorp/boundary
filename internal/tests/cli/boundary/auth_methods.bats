#!/usr/bin/env bats

load _auth
load _auth_methods
load _helpers

export NEW_AUTH_METHOD='test_auth_method'

@test "boundary/auth_method: can log in as unpriv user" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/auth_method: unpriv user can list auth methods" {
  run list_auth_methods
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/auth_method: log in as default user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/auth_method: can list auth methods" {
  run list_auth_methods
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/auth_method: can create a password auth method" {
  run create_password_auth_method $NEW_AUTH_METHOD
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/auth_method: can read an auth method" {
  local amid=$(auth_method_id $NEW_AUTH_METHOD)
  run read_auth_method $amid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/auth_method: can update an auth method" {
  local amid=$(auth_method_id $NEW_AUTH_METHOD)
  run update_password_auth_method $amid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/auth_method: can delete an auth method" {
  local amid=$(auth_method_id $NEW_AUTH_METHOD)
  run delete_auth_method $amid
  echo "$output"
  [ "$status" -eq 0 ]
}
