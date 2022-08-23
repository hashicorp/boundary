#!/usr/bin/env bats

load _auth
load _workers
load _helpers

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

# TODO: Add worker creation and deletion tests.

@test "boundary/workers: can list workers" {
	run list_workers
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/workers: can update worker's name" {
  local wid=$(worker_id)
  local name="test"
    run update_worker $wid $name
  echo "$output"
	[ "$status" -eq 0 ]
  worker_has_name $name
	[ "$status" -eq 0 ]
}

@test "boundary/workers: can read worker" {
  local wid=$(worker_id)
	run read_worker $wid
  echo "$output"
	[ "$status" -eq 0 ]
}

@test "boundary/workers: the worker contains default authorized-actions" {
  local wid=$(worker_id)
  local out=$(read_worker $wid)
	run has_default_worker_actions "$out"
  echo "$output"
	[ "$status" -eq 0 ]
}
