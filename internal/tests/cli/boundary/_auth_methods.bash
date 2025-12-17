# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

function create_password_auth_method() {
  local name=$1
  boundary auth-methods create password -name $name -format json
}

function read_auth_method() {
  local amid=$1
  boundary auth-methods read -id $amid -format json
}

function list_auth_methods() {
  boundary auth-methods list -format json
}

function delete_auth_method() {
  local amid=$1
  boundary auth-methods delete -id $amid -format json
}

function update_password_auth_method() {
  local amid=$1
  boundary auth-methods update password -id $amid -description "TEST"
}

function auth_method_id() {
  local name=$1
  strip $(list_auth_methods | jq -c ".items[] | select(.name != null) | select(.name | contains(\"$name\")) | .[\"id\"]")
}

function get_default_ldap_auth_method_id() {
  strip $(list_auth_methods | jq -c ".items[] | select(.type | contains(\"ldap\")) | .[\"id\"]")
}
