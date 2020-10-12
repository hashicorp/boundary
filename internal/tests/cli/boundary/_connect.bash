function connect_nc() {
  local id=$1
  echo "foo" | boundary connect -exec nc -target-id $id -- {{boundary.ip}} {{boundary.port}}
}
