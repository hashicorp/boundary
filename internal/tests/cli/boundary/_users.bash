function create_user() {
  boundary users create -scope-id global -name $1 -description 'test user'
}

function read_user() {
  boundary users read -id $1
}

function delete_user() {
  boundary users delete -id $1
}

function list_users() {
  boundary users list -format json
}

function assoc_user_acct() {
  boundary users add-accounts -account $1 -id $2
}

function user_id() {
  local user=$1
  strip $(list_users | jq -c ".[] | select(.name | contains(\"$user\")) | .[\"id\"]")
}
