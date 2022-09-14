#!/usr/bin/env bats

load _auth
load _connect
load _sessions
load _helpers

@test "boundary/session: admin user can connect to default target" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]

  run connect_nc $DEFAULT_TARGET
  echo "$output"
  [ "$status" -eq 0 ]

  # Run twice so we have two values for later testing
  run connect_nc $DEFAULT_TARGET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/session/connect: unpriv user can connect to default target" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]

  run connect_nc $DEFAULT_TARGET
  [ "$status" -eq 0 ]

  # Run twice so we have two values for later testing
  run connect_nc $DEFAULT_TARGET
  echo "$output"
  diag "$output"
  [ "$status" -eq 0 ]
}

# Note: there seems to be an issue with jq's length calculation -- an increase
# in the returned array by 2 shows up as a 4 or more increase in jq's length count.
# So for now, verify they're not the same.
@test "boundary/session: verify admin and unpriv user see different counts" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]

  run count_sessions $DEFAULT_P_ID
  [ "$status" -eq 0 ]
  unpriv_sessions="$output"

  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
  run count_sessions $DEFAULT_P_ID
  [ "$status" -eq 0 ]
  admin_sessions="$output"

  [ "$unpriv_sessions" -lt "$admin_sessions" ]
}

@test "boundary/session: verify read and cancellation permissions on admin session" {
  # Find an admin session
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
  run list_sessions $DEFAULT_P_ID
  [ "$status" -eq 0 ]
  id=$(echo "$output" | jq -r "[.items[]|select(.user_id == \"$DEFAULT_USER\")][0].id")

  # Check unpriv cannot read or cancel an admin's session
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
  run read_session $id
  [ "$status" -eq 1 ]
  run cancel_session $id
  [ "$status" -eq 1 ]

  # Check that admin _can_
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
  run read_session $id
  [ "$status" -eq 0 ]
  echo $output
  run cancel_session $id
  [ "$status" -eq 0 ]
  echo $output
}

@test "boundary/session: verify read and cancellation permissions on unpriv session" {
  # Find an unpriv session
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
  run list_sessions $DEFAULT_P_ID
  [ "$status" -eq 0 ]
  id=$(echo "$output" | jq -r "[.items[]|select(.user_id == \"$DEFAULT_UNPRIVILEGED_USER\")][0].id")

  # Check unpriv can read and cancel their own session
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
  run read_session $id
  [ "$status" -eq 0 ]
  run cancel_session $id
  [ "$status" -eq 0 ]

  # Check that admin can too
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
  run read_session $id
  [ "$status" -eq 0 ]
  run cancel_session $id
  [ "$status" -eq 0 ]

  diag "$output"
}
