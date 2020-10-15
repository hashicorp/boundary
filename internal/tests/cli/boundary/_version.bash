function version() {
  boundary version -format json
}

function version_is_valid() {
  ver=$($(strip version) | jq -c '.version' | cut -d 'v' -f2)
  if [ "$ver" == "null" ]; then
    return 1
  fi
  return 0 
}

function revision_is_valid() {
  len=$($(strip version) | jq -c '.revision' | cut -d '+' -f1 | wc -m)
  if [ "$len" -eq 42 ]; then
    return 0
  fi
  return 1
}
