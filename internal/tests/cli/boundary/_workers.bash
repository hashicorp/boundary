load _authorized_actions

function read_worker() {
  boundary workers read -id $1 -format json
}

function update_worker() {
  boundary workers update -id $1 -name $2 -version 0
}

function add_worker_tag() {
  boundary workers add-worker-tags -id $1 -tag $2 -version 0
}

function delete_worker() {
  boundary workers delete -id $1
}

function list_workers() {
  boundary workers list -format json
}

function worker_id() {
  # TODO: After we have creation tests, look up based
  #    on the worker's name.
  strip $(list_workers | jq -c ".items[] | .[\"id\"]")
}

function worker_has_name() {
  local name=$(strip $(list_workers | jq -c ".items[] | .[\"name\"]"))
  if [[ "$1" == "$name" ]]
    then
      return 0
    else
      return 1
    fi
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
