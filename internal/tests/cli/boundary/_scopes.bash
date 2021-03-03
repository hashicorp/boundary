load _authorized_actions

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
  
  strip $(list_scopes $sid | jq -c ".items[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}

function has_default_scope_actions() {
  local out=$1
  local actions=('read' 'update' 'delete')

  for action in ${actions[@]}; do
    $(has_authorized_action "$out" "$action") || {
      echo "failed to find $action action in output: $out"
      return 1 
    } 
  done
}
