function create_group() {
  boundary groups create -scope-id global -name $1 -description 'test group'
}

function read_group() {
  boundary groups read -id $1
}

function delete_group() {
  boundary groups delete -id $1
}

function list_groups() {
  boundary groups list -format json
}

function assoc_group_acct() {
  boundary groups add-members -member $1 -id $2
}

function group_id() {
  local group=$1
  strip $(list_groups | jq -c ".[] | select(.name | contains(\"$group\")) | .[\"id\"]")
}

function group_member_ids() {
  local gid=$1
  boundary groups read -id $gid -format json | jq '.["members"][]["id"]'  
}

function group_has_member_id() {
  local mid=$1
  local gid=$2
  ids=$(group_member_ids $gid)
  for id in $ids; do
    if [ $(strip "$id") == "$mid" ]; then
      return 0 
    fi
  done
  return 1 
}
