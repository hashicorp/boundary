function create_host() {
  local name=$1
  local hcid=$2
  
  boundary hosts create static \
    -name $name \
    -description 'test host' \
    -address '1.1.1.1' \
    -host-catalog-id $hcid
}

function read_host() {
  boundary hosts read -id $1
}

function delete_host() {
  boundary hosts delete -id $1
}

function list_hosts() {
  boundary hosts list -host-catalog-id $1 -format json
}

function host_id() {
  local name=$1
  local hcid=$2
  
  strip $(list_hosts $hcid | jq -c ".[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}
