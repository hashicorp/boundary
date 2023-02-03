load _authorized_actions

function create_role() {
  local sid=$1
  local name=$2
  local gsid=$3

  boundary roles create \
    -scope-id $sid \
    -name $name \
    -description 'test role' \
    -grant-scope-id $gsid
}

function read_role() {
  boundary roles read -id $1 -format json
}

function delete_role() {
  boundary roles delete -id $1 -format json
}

function list_roles() {
  boundary roles list -scope-id $1 -format json
}

function assoc_role_grant() {
  local grant=$1
  local id=$2

  boundary roles add-grants -grant $grant -id $id
}

function assoc_role_principal() {
  local principal=$1
  local id=$2

  boundary roles add-principals -principal $principal -id $id
}

function remove_role_grant() {
  local grant=$1
  local id=$2

  boundary roles remove-grants -grant $grant -id $id
}

function remove_role_principal() {
  local principal=$1
  local id=$2

  boundary roles remove-principals -principal $principal -id $id
}

function role_id() {
  local name=$1
  local sid=$2
  strip $(list_roles $sid | jq -c ".items[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}

function role_principal_ids() {
  local rid=$1
  strip $(read_role $rid | jq '.item["principals"][]["id"]')
}

function role_has_principal_id() {
  local rid=$1
  local pid=$2
  local ids=$(role_principal_ids $rid)
  for id in $ids; do
    if [ $(strip "$id") == "$pid" ]; then
      return 0
    fi
  done
  return 1
}

function role_grants() {
  local rid=$1
  read_role $rid | jq -rc '.item.grant_strings | @sh'
}

function role_has_grant() {
  local rid=$1
  local g=$2
  local hasgrants=$(role_grants $rid)
  for grant in $hasgrants; do
    if [ $(strip_all "$grant") == "$g" ]; then
      return 0
    fi
  done
  return 1
}

function has_default_role_actions() {
  local out=$1
  local actions=('read' 'update' 'delete' 'add-principals' 'set-principals' 'remove-principals' 'add-grants' 'set-grants' 'remove-grants')

  for action in ${actions[@]}; do
    $(has_authorized_action "$out" "$action") || {
      echo "failed to find $action action in output: $out"
      return 1
    }
  done
}
