#!/usr/bin/env bats

load _auth
load _workers
load _helpers

export NEW_WORKER='test'

export NEW_UPDATED_WORKER='newtest'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/workers: can create $NEW_WORKER worker" {
  run create_worker $NEW_WORKER
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/workers: can not create already created $NEW_WORKER worker" {
  run create_worker $NEW_WORKER
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/workers: can read $NEW_WORKER worker" {
  local wid=$(worker_id $NEW_WORKER)
  run read_worker $wid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/workers: can list workers" {
  run list_workers
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/workers: the worker contains default authorized-actions" {
  local wid=$(worker_id $NEW_WORKER)
  local out=$(read_worker $wid)
  run has_default_worker_actions "$out"
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/workers: can update worker's name" {
  local wid=$(worker_id $NEW_WORKER)
  run update_worker $wid $NEW_UPDATED_WORKER
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/workers: can delete $NEW_UPDATED_WORKER worker once" {
  local wid=$(worker_id $NEW_UPDATED_WORKER)
  run delete_worker $wid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]

  run delete_worker $wid
  echo "$output"
  run has_status_code "$output" "404"
  [ "$status" -eq 0 ]
}
