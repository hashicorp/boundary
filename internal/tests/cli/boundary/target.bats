#!/usr/bin/env bats

load _auth
load _connect
load _targets
load _helpers


@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/target/connect: default user can connect to default target" {
  run connect_nc $DEFAULT_TARGET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: default user can create target" {
  run create_tcp_target $DEFAULT_P_ID 22 $TGT_NAME
  [ "$status" -eq 0 ]
}

@test "boundary/target: default user can not create already created target" {
  run create_tcp_target $DEFAULT_P_ID 22 $TGT_NAME
  [ "$status" -eq 1 ]
}

@test "boundary/target: default user can read created target" {
  local id=$(target_id $DEFAULT_P_ID $TGT_NAME)
  run read_target $id
  [ "$status" -eq 0 ]
}

@test "boundary/target: the $TGT_NAME target contains default authorized-actions" {
  local id=$(target_id $DEFAULT_P_ID $TGT_NAME)
  local out=$(read_target $id)

	run has_default_target_actions "$out" 
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/target: default user can add default host set to created target" {
  local id=$(target_id $DEFAULT_P_ID $TGT_NAME)
  run assoc_host_sets $id $DEFAULT_HOST_SET  
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: created target has default host set" {
  local id=$(target_id $DEFAULT_P_ID $TGT_NAME)
  run target_has_host_set_id $id $DEFAULT_HOST_SET  
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target/connect: default user can connect to created target" {
  local id=$(target_id $DEFAULT_P_ID $TGT_NAME)
  run connect_nc $id
  echo "connecting to $id: $output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: default user can delete target" {
  local id=$(target_id $DEFAULT_P_ID $TGT_NAME)
  run delete_target $id
  [ "$status" -eq 0 ]
}

@test "boundary/target: default user can not read deleted target" {
  local id=$(target_id $DEFAULT_P_ID $TGT_NAME) 
  run read_target $id
  [ "$status" -eq 1 ]
}
