load _authorized_actions

function create_user() {
  boundary users create -scope-id global -name $1 -description 'test user'
}

function read_user() {
  boundary users read -id $1 -format json
}

function delete_user() {
  boundary users delete -id $1 -format json
}

function list_users() {
  boundary users list -format json
}

function assoc_user_acct() {
  boundary users add-accounts -account $1 -id $2
}

function has_default_user_actions() {
  # tests that the user resource contains default actions
  local out=$1
  local actions=('read' 'update' 'delete' 'add-accounts' 'set-accounts' 'remove-accounts')

  for action in ${actions[@]}; do
    $(has_authorized_action "$out" "$action") || {
      echo "failed to find $action action in output: $out"
      return 1
    }
  done
}

function user_id() {
  local user=$1
  strip $(list_users | jq -c ".items[] | select(.name | contains(\"$user\")) | .[\"id\"]")
}
