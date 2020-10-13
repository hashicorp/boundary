function create_scope() {
  local parent=$1
  local name=$2
  echo "name $name scope $parent"
  boundary scopes create -name $name -scope-id $parent
}

function read_scope() {
  local sid=$1

  boundary scopes read -id $sid -format json
}

function delete_scope() {
  local sid=$1

  boundary scopes delete -id $sid
}

function list_scopes() {
  boundary scopes list -scope-id $1 -format json
}

function scope_id() {
  local name=$1
  local sid=$2
  
  strip $(list_scopes $sid | jq -c ".[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}
