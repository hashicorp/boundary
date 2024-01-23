#!/usr/bin/env bats

load _auth
load _connect
load _targets
load _helpers
load _target_host_sources


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
}

@test "boundary/target: unpriv user can read default target" {
  run read_target $DEFAULT_TARGET
  [ "$status" -eq 0 ]
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
  run add_target_host_sources $id $DEFAULT_HOST_SET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: created target has default host set" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  local format="json"
  run target_has_host_source_id $id $format $DEFAULT_HOST_SET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target/connect: default user can connect to created target" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run connect_nc $id
  echo "connecting to $id: $output"
  [ "$status" -eq 0 ]
}

@test "boundary/target/client_port: admin user set can set a client port" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run update_tcp_target -id $id -default-client-port 1234
  echo "$output"
  [ "$status" -eq 0 ]

  run read_target $id
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  echo "$got"
  run field_eq "$got" ".item.attributes.default_client_port" "1234"
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

@test "boundary/target: create target with a network address" {
  run create_tcp_target_with_addr $DEFAULT_P_ID "localhost" 22 $TGT_NAME_WITH_ADDR
  [ "$status" -eq 0 ]
}

@test "boundary/target: cannot assign an host source to a target with an address" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME_WITH_ADDR)
  run add_target_host_sources $id $DEFAULT_HOST_SET
  [ "$status" -eq 1 ]
}

@test "boundary/target: can assign an host source to a target after deleting address" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME_WITH_ADDR)
  run update_address $id "null"
  [ "$status" -eq 0 ]
  run add_target_host_sources $id $DEFAULT_HOST_SET
  [ "$status" -eq 0 ]
}

@test "boundary/target: cannot assign an address to a target with an host source" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME_WITH_ADDR)
  run update_address $id "localhost"
  [ "$status" -eq 1 ]
}

@test "boundary/target: can assign an an address to a target after deleting host source" {
  local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME_WITH_ADDR)
  run remove_target_host_sources $id $DEFAULT_HOST_SET
  [ "$status" -eq 0 ]
  run update_address $id "localhost"
  [ "$status" -eq 0 ]
}
