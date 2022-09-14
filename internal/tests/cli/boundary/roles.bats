#!/usr/bin/env bats

load _accounts
load _auth
load _roles
load _helpers

export NEW_ROLE='test'
export NEW_GRANT='id=*;type=*;actions=create,read,update,delete,list'

@test "boundary/login: can login as default principal" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/roles: can add $NEW_ROLE role to global scope granting rights in default org scope" {
	run create_role 'global' $NEW_ROLE $DEFAULT_O_ID
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/roles: can not add already created $NEW_ROLE role" {
	run create_role 'global' $NEW_ROLE $DEFAULT_O_ID
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/roles: can read $NEW_ROLE role" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
	run read_role $rid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/roles: the $NEW_ROLE role contains default authorized-actions" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  local out=$(read_role $rid)

	run has_default_role_actions "$out"
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/role/add-principals: can associate $NEW_ROLE role with default principal" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  run assoc_role_principal $DEFAULT_USER $rid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/role/add-principals: $NEW_ROLE role contains default principal" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  run role_has_principal_id $rid $DEFAULT_USER
  echo "$output"
  diag "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/role/remove-principals: can remove default principal from $NEW_ROLE role" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  run remove_role_principal $DEFAULT_USER $rid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/role/remove-principals: $NEW_ROLE role no longer contains default principal" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  run role_has_principal_id $rid $DEFAULT_USER
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/role/add-grants: can associate $NEW_ROLE role with $NEW_GRANT grant" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  run assoc_role_grant $NEW_GRANT $rid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/role/add-grantss: $NEW_ROLE role contains $NEW_GRANT grant" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  run role_has_grant $rid $NEW_GRANT
  echo "$output"
  diag "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/role/remove-grants: can remove $NEW_GRANT grant from $NEW_ROLE role" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  run remove_role_grant $NEW_GRANT $rid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/role/remove-grants: $NEW_ROLE role no longer contains $NEW_GRANT grant" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  run role_has_grant $rid $NEW_GRANT
  echo "$output"
  diag "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/role: can delete $NEW_ROLE role" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
  run delete_role $rid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/roles: can not read deleted $NEW_ROLE role" {
  local rid=$(role_id $NEW_ROLE $DEFAULT_GLOBAL)
	run read_role $rid
  echo "$output"
  diag "$output"
	[ "$status" -eq 1 ]
}
