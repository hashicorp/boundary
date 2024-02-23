#!/usr/bin/env bats

load _auth
load _billing
load _helpers

@test "boundary/billing: can login as admin user" {
  run login $DEFAULT_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/billing: admin user can get last two months" {
  run active_users_last_two_months
  [ "$status" -eq 0 ]
  run has_status_code "$output" "200"
}

@test "boundary/billing: admin user can get report with start time" {
  run active_users_start_time "2023-09"
  [ "$status" -eq 0 ]
  run has_status_code "$output" "200"
}

@test "boundary/billing: admin user can get report with start and end times" {
  run active_users_start_time_and_end_time "2023-09" "2023-12"
  [ "$status" -eq 0 ]
  run has_status_code "$output" "200"
}

@test "boundary/billing: cannot get report with end time before start time" {
  run active_users_start_time_and_end_time "2023-09" "2023-08"
  [ "$status" -eq 1 ]
}

@test "boundary/billing: cannot get report with only end time" {
  run active_users_end_time "2023-09" 
  [ "$status" -eq 1 ]
}

# unpriv tests
@test "boundary/billing: can login as unpriv user" {
  run login $DEFAULT_UNPRIVILEGED_LOGIN
  [ "$status" -eq 0 ]
}

@test "boundary/billing: default user cannot get last two months" {
  run active_users_last_two_months
  [ "$status" -eq 1 ]
}

@test "boundary/billing: default user cannot get report with start time" {
  run active_users_start_time "2023-09"
  [ "$status" -eq 1 ]
  run has_status_code "$output" "200"
}

@test "boundary/billing: default user cannot get report with start and end times" {
  run active_users_start_time_and_end_time "2023-09" "2023-12"
  [ "$status" -eq 1 ]
  run has_status_code "$output" "200"
}