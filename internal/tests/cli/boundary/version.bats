#!/usr/bin/env bats

load _helpers
load _version

export NEW_USER='test'

@test "boundary/version: can run version command" {
  run version
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/version: version output is valid" {
  run version_is_valid 
  echo "$output"
  [ "$status" -eq 0 ]
}


@test "boundary/version: revision output is valid" {
  run revision_is_valid 
  echo "$output"
  [ "$status" -eq 0 ]
}
