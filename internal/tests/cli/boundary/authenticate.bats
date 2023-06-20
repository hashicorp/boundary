#!/usr/bin/env bats

load _auth
load _helpers
load _auth_tokens

export NEW_USER='test'

@test "boundary/authenticate password: can login as unpriv user" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
  run logout_cmd
  [ "$status" -eq 0 ]
}

@test "boundary/authenticate ldap: can login as unpriv user" {
  run login_ldap $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
  run logout_cmd
  [ "$status" -eq 0 ]
}


