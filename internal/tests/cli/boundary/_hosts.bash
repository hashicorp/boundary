load _authorized_actions

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
  boundary hosts read -id $1 -format json
}

function delete_host() {
  boundary hosts delete -id $1 -format json
}

function list_hosts() {
  boundary hosts list -host-catalog-id $1 -format json
}

function host_id() {
  local name=$1
  local hcid=$2

  strip $(list_hosts $hcid | jq -c ".items[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}

function has_default_host_actions() {
  local out=$1
  local actions=('read' 'update' 'delete')

  for action in ${actions[@]}; do
    $(has_authorized_action "$out" "$action") || {
      echo "failed to find $action action in output: $out"
      return 1
    }
  done
}
