load _authorized_actions

function create_username_password_credential() {
  local name=$1
  local sid=$2
  local user=$3
  local pass=$4
  
  boundary credentials create username-password \
    -name $name \
    -description 'test username password credential' \
    -credential-store-id $sid \
    -username $user \
    -password $pass
}

function read_credential() {
  boundary credentials read -id $1 -format json
}

function delete_credential() {
  boundary credentials delete -id $1
}

function list_credentials() {
  boundary credentials list -credential-store-id $1 -format json
}

function credential_id() {
  local name=$1
  local sid=$2
  
  strip $(list_credentials $sid | jq -c ".items[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}
