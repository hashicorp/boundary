#!/usr/bin/env bats

load _auth
load _helpers
load _targets
load _generics


@test "boundary/generic: can log in as admin user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/generic: admin user can create target" {
  run create_tcp_target $DEFAULT_P_ID 22 $TGT_NAME
  echo $output
  [ "$status" -eq 0 ]
}

@test "boundary/generic: admin user can read target with generic read" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run generic_read $id
  echo $output
  [ "$status" -eq 0 ]
}

@test "boundary/generic: admin user can update target with generic update" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run generic_update_name $id $UPDATE_NAME
  echo $output
  [ "$status" -eq 0 ]
}

@test "boundary/generic: admin user can check that the update worked with generic read" {
  local id=$(target_id_from_name $DEFAULT_P_ID $UPDATE_NAME)
  echo $id
  run generic_read $id
  echo $output
  [ "$status" -eq 0 ]
}

@test "boundary/generic: admin user can delete target with generic delete" {
  local id=$(target_id_from_name $DEFAULT_P_ID $UPDATE_NAME)
  run generic_delete $id
  echo $output
  [ "$status" -eq 0 ]
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}