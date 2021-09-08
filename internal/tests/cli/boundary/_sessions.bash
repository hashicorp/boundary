load _authorized_actions

function list_sessions() {
  boundary sessions list -scope-id $1 -format json
}

function count_sessions() {
  list_sessions $1 | jq '.items | length'
}

function cancel_session() {
  boundary sessions cancel -id $1
}

function read_session() {
  boundary sessions read -id $1
}
