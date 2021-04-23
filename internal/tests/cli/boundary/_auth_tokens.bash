function read_token() {
  if [[ "x$1" == "x" ]]
  then
    echo "y" | boundary auth-tokens read
  else
    boundary auth-tokens read -id $1
  fi
}

function delete_token() {
  if [[ "x$1" == "x" ]]
  then
    echo "y" | boundary auth-tokens delete
  else
    boundary auth-tokens delete -id $1
  fi
}

function token_id() {
  local tid=$1
  strip $(read_token $tid | jq '.item.id') 
}