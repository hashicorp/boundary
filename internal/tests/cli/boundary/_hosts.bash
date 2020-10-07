
function create_host() {
  local name=$1
  local addr=$2
  boundary hosts create static -name $name -address $addr
}

function read_host() {
  boundary hosts read -id $1
}

function delete_host() {
  boundary hosts delete -id $1
}

function list_hosts() {
  boundary hosts list -scope-id $1 -format json
}

function host_id() {
  local sid=$1
  local name=$2
  strip $(list_hosts $sid | jq -c ".[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}
