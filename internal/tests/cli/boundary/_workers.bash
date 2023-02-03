load _authorized_actions

function read_worker() {
  boundary workers read -id $1 -format json
}

function create_worker() {
  boundary workers create controller-led \
    -name $1 \
    -description 'test worker'
}

function update_worker() {
  boundary workers update -id $1 -name $2 -version 0
}

function delete_worker() {
  boundary workers delete -id $1 -format json
}

function list_workers() {
  boundary workers list -format json
}

function worker_id() {
  local id=$1
  strip $(list_workers | jq -c ".items[] | select(.name != null) | select(.name | contains(\"$id\")) | .[\"id\"]")
}

function has_default_worker_actions() {
  local out=$1
  local actions=('read' 'update' 'delete' 'add-worker-tags' 'set-worker-tags' 'remove-worker-tags')

  for action in ${actions[@]}; do
    $(has_authorized_action "$out" "$action") || {
      echo "failed to find $action action in output: $out"
      return 1
    }
  done
}
