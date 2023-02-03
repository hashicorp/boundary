load _authorized_actions

export TGT_NAME='test'
export TGT_NAME_WITH_ADDR='test-address'

function create_tcp_target() {
  local sid=$1
  local port=$2
  local name=$3
  boundary targets create tcp \
    -default-port $port \
    -name $name \
    -scope-id $sid \
    -format json
}

function create_tcp_target_with_addr() {
  local sid=$1
  local addr=$2
  local port=$3
  local name=$4
  boundary targets create tcp \
    -address $addr \
    -default-port $port \
    -name $name \
    -scope-id $sid \
    -format json
}

function read_target() {
  boundary targets read -id $1 -format json
}

function delete_target() {
  boundary targets delete -id $1 -format json
}

function list_targets() {
  boundary targets list -scope-id $1 -format json
}

function update_address() {
  local id=$1
  local addr=$2
  boundary targets update tcp -id $id -address $2
}

function assoc_host_sources() {
  local id=$1
  local hst=$2
  boundary targets add-host-sources -id $id -host-source $hst
}

function remove_host_sources() {
  local id=$1
  local hst=$2
  boundary targets remove-host-sources -id $id -host-source $hst
}

function target_id_from_name() {
  local sid=$1
  local name=$2
  strip $(list_targets $sid | jq -c ".items[] | select(.name | contains(\"$name\")) | .[\"id\"]")
}

function target_host_source_ids() {
  local tid=$1
  boundary targets read -id $tid -format json | jq '.item.host_sources[].id'
}

function target_has_host_source_id() {
  local tid=$1
  local hsid=$2

  ids=$(target_host_source_ids $tid)
  for id in $ids; do
    if [ $(strip "$id") == "$hsid" ]; then
      return 0
    fi
  done
  return 1
}

function has_default_target_actions() {
  local out=$1
  local actions=('read' 'update' 'delete' 'add-host-sources' 'set-host-sources' 'remove-host-sources' 'authorize-session')

  for action in ${actions[@]}; do
    $(has_authorized_action "$out" "$action") || {
      echo "failed to find $action action in output: $out"
      return 1
    }
  done
}
