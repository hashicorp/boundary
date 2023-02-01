load _authorized_actions

function create_host_catalog() {
  local name=$1
  local sid=$2
  echo "sid $sid"
  boundary host-catalogs create static \
    -scope-id $sid \
    -name $name \
    -description 'test host catalog'
}

function read_host_catalog() {
  boundary host-catalogs read -id $1 -format json
}

function delete_host_catalog() {
  boundary host-catalogs delete -id $1 -format json
}

function list_host_catalogs() {
  boundary host-catalogs list -scope-id $1 -format json
}

function host_catalog_id() {
  local id=$1
  local sid=$2
  strip $(list_host_catalogs $sid | jq -c ".items[] | select(.name | contains(\"$id\")) | .[\"id\"]")
}

function has_default_host_catalog_actions() {
  local out=$1
  local actions=('read' 'update' 'delete')

  for action in ${actions[@]}; do
    $(has_authorized_action "$out" "$action") || {
      echo "failed to find $action action in output: $out"
      return 1
    }
  done
}
