load _authorized_actions

function create_static_credential_store() {
  local name=$1
  local sid=$2
  
  boundary credential-stores create static \
    -name $name \
    -description 'test static credential store' \
    -scope-id $sid
}

function read_credential_store() {
  boundary credential-stores read -id $1 -format json
}

function delete_credential_store() {
  boundary credential-stores delete -id $1
}

function list_credential_stores() {
  boundary credential-stores list -scope-id $1 -format json
}

function credential_store_id() {
  local name=$1
  local sid=$2
  
  strip $(list_credential_stores $sid | jq -c ".items[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}
