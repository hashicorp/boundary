# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

function read_token() {
  if [[ "x$1" == "x" ]]
  then
    echo "y" | boundary auth-tokens read
  else
    boundary auth-tokens read -id $1 -format json
  fi
}

function delete_token() {
  if [[ "x$1" == "x" ]]
  then
    echo "y" | boundary auth-tokens delete
  else
    boundary auth-tokens delete -id $1
  fi
}

function token_id() {
  local tid=$1
  strip $(read_token $tid | jq '.item.id')
}

function logout_cmd() {
  boundary logout
}

function get_token() {
  boundary config get-token
}

function read_token_no_keyring() {
  boundary auth-tokens read -keyring-type=none -id $1
}

function list_tokens() {
  boundary auth-tokens list -format json
}
