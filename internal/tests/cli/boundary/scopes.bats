#!/usr/bin/env bats

load _auth
load _scopes
load _helpers

export NEW_ORG='test_org'
export NEW_PROJECT='test_project'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/scopes: can list keys at global scope" {
	run list_scope_keys $DEFAULT_GLOBAL
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can rotate keys at global scope" {
	run rotate_scope_keys $DEFAULT_GLOBAL
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can list key version destruction jobs at global scope" {
	run list_key_version_destruction_jobs $DEFAULT_GLOBAL
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can create $NEW_ORG organization level scope" {
	run create_scope $DEFAULT_GLOBAL $NEW_ORG
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can read $NEW_ORG organization level scope" {
  local sid=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
	run read_scope $sid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: the $NEW_ORG scope contains default org authorized-actions" {
  local sid=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
  local out=$(read_scope $sid)

	run has_default_scope_actions "$out" 
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can list keys at $NEW_ORG organization level scope" {
  local sid=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
	run list_scope_keys $sid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can rotate keys at $NEW_ORG organization level scope" {
  local sid=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
	run rotate_scope_keys $sid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can list key version destruction jobs at $NEW_ORG organization level scope" {
  local sid=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
	run list_key_version_destruction_jobs $sid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can create $NEW_PROJECT project level scope" {
  local parent=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
	run create_scope $parent $NEW_PROJECT
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can read $NEW_PROJECT project level scope" {
  local parent=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
  local sid=$(scope_id $NEW_PROJECT $parent)
	run read_scope $sid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: the $NEW_PROJECT scope contains default project authorized-actions" {
  local parent=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
  local sid=$(scope_id $NEW_PROJECT $parent)
  local out=$(read_scope $sid)

	run has_default_scope_actions "$out" 
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can list keys at $NEW_PROJECT project level scope" {
  local parent=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
  local sid=$(scope_id $NEW_PROJECT $parent)
	run list_scope_keys $sid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can rotate keys at $NEW_PROJECT project level scope" {
  local parent=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
  local sid=$(scope_id $NEW_PROJECT $parent)
	run rotate_scope_keys $sid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can list key version destruction jobs at $NEW_PROJECT project level scope" {
  local parent=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
  local sid=$(scope_id $NEW_PROJECT $parent)
	run list_key_version_destruction_jobs $sid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can delete $NEW_PROJECT project level scope" {
  local parent=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
  local sid=$(scope_id $NEW_PROJECT $parent)
	run delete_scope $sid
  echo "$output"
  run has_status_code "$output" "204"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can not read deleted $NEW_PROJECT project level scope" {
  local parent=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
  local sid=$(scope_id $NEW_PROJECT $parent)
	run read_scope $sid
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/scopes: can delete $NEW_ORG organization level scope" {
  local sid=$(scope_id $NEW_ORG $DEFAULT_GLOBAL)
	run delete_scope $sid
  echo "$output"
  run has_status_code "$output" "204"
	[ "$status" -eq 0 ]
}

@test "boundary/scopes: can not read deleted $NEW_ORG organization level scope" {
  local sid=$(scope_id $NEW_PROJECT $DEFAULT_GLOBAL)
	run read_scope $sid
  echo "$output"
	[ "$status" -eq 1 ]
}
