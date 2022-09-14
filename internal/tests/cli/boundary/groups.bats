#!/usr/bin/env bats

load _accounts
load _auth
load _groups
load _helpers

export NEW_GROUP='test'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/groups: can add $NEW_GROUP group" {
	run create_group $NEW_GROUP
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/groups: can not add already created $NEW_GROUP group" {
	run create_group $NEW_GROUP
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/groups: can read $NEW_GROUP group" {
  local gid=$(group_id $NEW_GROUP)
	run read_group $gid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/groups: the $NEW_GROUP group contains default authorized-actions" {
  local gid=$(group_id $NEW_GROUP)
  local out=$(read_group $gid)

	run has_default_group_actions "$out"
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/group/add-members: can associate $NEW_GROUP group with default user" {
  local gid=$(group_id $NEW_GROUP)
  run assoc_group_acct 'u_1234567890' $gid
  echo "$output"
  diag "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/group/add-members: $NEW_GROUP group contains default user" {
  local gid=$(group_id $NEW_GROUP)
  run group_has_member_id 'u_1234567890' $gid
  echo "$output"
  diag "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/group: can delete $NEW_GROUP group" {
  local gid=$(group_id $NEW_GROUP)
  run delete_group $gid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/groups: can not read deleted $NEW_GROUP group" {
  local gid=$(group_id $NEW_GROUP)
	run read_group $gid
  echo "$output"
	[ "$status" -eq 1 ]
}
