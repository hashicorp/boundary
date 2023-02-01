function create_account() {
  export BP="${DEFAULT_PASSWORD}"
  boundary accounts create password -login-name $1 -password env://BP -auth-method-id $DEFAULT_AMPW
}

function read_account() {
  boundary accounts read -id $1
}

function delete_account() {
  boundary accounts delete -id $1 -format json
}

function list_accounts() {
  boundary accounts list -auth-method-id $DEFAULT_AMPW -format json
}

function account_id() {
  local acct=$1
  strip $(list_accounts | jq -c ".items[] | select(.attributes.login_name | contains(\"$acct\")) | .[\"id\"]")
}
