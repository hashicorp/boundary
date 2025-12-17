# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

load _authorized_actions

function create_username_password_credential() {
  local name=$1
  local sid=$2
  local user=$3
  local pass=$4

  export BP="${pass}"
  boundary credentials create username-password \
    -name $name \
    -description 'test username password credential' \
    -credential-store-id $sid \
    -username $user \
    -password env://BP
}


function create_username_password_domain_credential_with_domain() {
  local name=$1
  local sid=$2
  local user=$3
  local pass=$4
  local domain=$5

  export BP="${pass}"
  boundary credentials create username-password-domain \
    -name $name \
    -description 'test username password domain credential with domain' \
    -credential-store-id $sid \
    -username $user \
    -password env://BP \
    -domain $domain
}

function create_username_password_domain_credential() {
  local name=$1
  local sid=$2
  local user=$3
  local pass=$4

  export BP="${pass}"
  boundary credentials create username-password-domain \
    -name $name \
    -description 'test username password domain credential with domain parsed from username' \
    -credential-store-id $sid \
    -username $user \
    -password env://BP
}

function create_json_credential() {
  local name=$1
  local sid=$2
  local args=$3

  boundary credentials create json \
    -name $name \
    -description 'test json credential' \
    -credential-store-id $sid \
    $args
}

function create_password_credential() {
  local name=$1
  local sid=$2
  local pass=$3

  export BP="${pass}"
  boundary credentials create password \
    -name $name \
    -description 'test password credential' \
    -credential-store-id $sid \
    -password env://BP
}

function read_credential() {
  boundary credentials read -id $1 -format json
}

function delete_credential() {
  boundary credentials delete -id $1 -format json
}

function list_credentials() {
  boundary credentials list -credential-store-id $1 -format json
}

function credential_id() {
  local name=$1
  local sid=$2

  strip $(list_credentials $sid | jq -c ".items[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}
