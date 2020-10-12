function create_host_catalog() {
  local sid=$1
  local name=$2
  boundary host-catalogs create static -scope-id $sid -name $name -description 'test host catalog'
}

function read_host_catalog() {
  boundary hosts read -id $1
}

function delete_host_catalog() {
  boundary hosts delete -id $1
}

function list_host_catalogs() {
  boundary host-catalogs list -scope-id $1 -format json
}

function host_catalog_id() {
  local id=$1
  local sid=$2
  strip $(list_host_catalogs $sid | jq -c ".[] | select(.name | contains(\"$id\")) | .[\"id\"]")
}
