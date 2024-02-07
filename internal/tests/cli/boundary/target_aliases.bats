#!/usr/bin/env bats

load _auth
load _connect
load _aliases
load _helpers
load _targets
load _targets_alias

export ALIAS_VALUE='target.alias'

@test "boundary/login: can login as admin user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/alias: admin user can create target alias" {
  run create_target_alias $ALIAS_VALUE $DEFAULT_TARGET
  echo $output
  [ "$status" -eq 0 ]
}

@test "boundary/alias/target: admin user can connect to default target using alias" {
  run connect_alias $ALIAS_VALUE
  [ "$status" -eq 0 ]
}

@test "boundary/alias/target: admin user can read default target using alias" {
  run read_target_by_alias $ALIAS_VALUE
  [ "$status" -eq 0 ]
}

@test "boundary/login: can login as unpriv user" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/alias/target: unpriv user can connect to default target" {
  run connect_alias $ALIAS_VALUE
  [ "$status" -eq 0 ]
}

@test "boundary/alias/target: unpriv user can read default target" {
  run read_target_by_alias $ALIAS_VALUE
  [ "$status" -eq 0 ]
}

@test "boundary/alias/target: login back in as admin user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/target: admin user can create target" {
  run create_tcp_target $DEFAULT_P_ID 22 $TGT_NAME
  echo $output
  [ "$status" -eq 0 ]
}

@test "boundary/target: admin user can update alias to use created target" {
  local aid=$(alias_id_from_target_alias $ALIAS_VALUE)
  local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
  run update_target_alias_destination_id $aid $tid
  echo $output
  [ "$status" -eq 0 ]
}

@test "boundary/target: admin user can read created target using alias" {
  run read_target_by_alias $ALIAS_VALUE
  [ "$status" -eq 0 ]
}

@test "boundary/alias/target: admin user can add default host set to created target using an alias" {
  run add_target_host_sources_by_alias $ALIAS_VALUE $DEFAULT_HOST_SET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/alias/target: created target has default host set" {
  local format="json"
  run target_has_host_source_id_by_alias $ALIAS_VALUE $format $DEFAULT_HOST_SET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/alias/target: default user can connect to created target using alias" {
  run connect_alias $ALIAS_VALUE
  echo "connecting to $ALIAS_VALUE: $output"
  [ "$status" -eq 0 ]
}

# Currently not working- there is a bug with how attributes get set with an alias
@test "boundary/alias/target: admin user set can set a client port using an alias" {
  run update_tcp_target $ALIAS_VALUE -default-client-port 1234
  echo "$output"
  [ "$status" -eq 0 ]

  run read_target_by_alias $ALIAS_VALUE
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  echo "$got"
  run field_eq "$got" ".item.attributes.default_client_port" "1234"
  [ "$status" -eq 0 ]
}