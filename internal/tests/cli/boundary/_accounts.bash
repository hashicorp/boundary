function create_account() {
  boundary accounts create password -login-name $1 -password $DEFAULT_PASSWORD -auth-method-id $DEFAULT_AMPW
}

function read_account() {
  boundary accounts read -id $1
}

function delete_account() {
  boundary accounts delete -id $1
}

function list_accounts() {
  boundary accounts list -auth-method-id $DEFAULT_AMPW -format json
}

function account_id() {
  local acct=$1
  strip $(list_accounts | jq -c ".items[] | select(.attributes.login_name | contains(\"$acct\")) | .[\"id\"]")
}
