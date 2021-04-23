#!/usr/bin/env bats

load _auth
load _auth_tokens
load _helpers

export NEW_USER='test'

@test "boundary/token: can login as unpriv user" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/token: can read own token with no id given" {
  run read_token ""
  [ "$status" -eq 0 ]
}

@test "boundary/token: can read own token with self given" {
  run read_token "self"
  [ "$status" -eq 0 ]
}

@test "boundary/token: can read own token id given" {
  local tid=$(token_id "self")
  run read_token "$tid"
  [ "$status" -eq 0 ]
}

@test "boundary/token: can delete own token with no id given" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
  run delete_token ""
  [ "$status" -eq 0 ]
  run read_token ""
  [ "$status" -eq 1 ]
}

@test "boundary/token: can delete own token with self given" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
  run delete_token "self"
  [ "$status" -eq 0 ]
  run read_token ""
  [ "$status" -eq 1 ]
}

@test "boundary/token: can delete own token with id given" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
  local tid=$(token_id "self")
  run delete_token "$tid"
  [ "$status" -eq 0 ]
  run read_token "$tid"
  [ "$status" -eq 1 ]
}