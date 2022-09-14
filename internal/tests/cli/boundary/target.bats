#!/usr/bin/env bats

load _auth
load _connect
load _targets
load _helpers


@test "boundary/login: can login as admin user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/target/connect: admin user can connect to default target" {
  run connect_nc $DEFAULT_TARGET
  [ "$status" -eq 0 ]
}

@test "boundary/target: admin user can read default target" {
  run read_target $DEFAULT_TARGET
  [ "$status" -eq 0 ]
}

@test "boundary/login: can login as unpriv user" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/target/connect: unpriv user can connect to default target" {
  run connect_nc $DEFAULT_TARGET
  [ "$status" -eq 0 ]
  diag "$output"
}

@test "boundary/target: unpriv user can not read default target" {
  run read_target $DEFAULT_TARGET
  [ "$status" -eq 1 ]
}

@test "boundary/login: login back in as admin user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/target: admin user can create target" {
  run create_tcp_target $DEFAULT_P_ID 22 $TGT_NAME
  echo $output
  [ "$status" -eq 0 ]
}

@test "boundary/target: admin user can not create already created target" {
  run create_tcp_target $DEFAULT_P_ID 22 $TGT_NAME
  [ "$status" -eq 1 ]
}

@test "boundary/target: admin user can read created target" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run read_target $id
  [ "$status" -eq 0 ]
}

@test "boundary/target: the $TGT_NAME target contains default authorized-actions" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  local out=$(read_target $id)

	run has_default_target_actions "$out"
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/target: admin user can add default host set to created target" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run assoc_host_sources $id $DEFAULT_HOST_SET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: created target has default host set" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run target_has_host_source_id $id $DEFAULT_HOST_SET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target/connect: default user can connect to created target" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run connect_nc $id
  echo "connecting to $id: $output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: default user can delete target" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run delete_target $id
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/target: default user can not read deleted target" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run read_target $id
  [ "$status" -eq 1 ]
}
