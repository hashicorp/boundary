#!/bin/bash
terraform apply

export BOUNDARY_ADDR=http://127.0.0.1:9200

PG_IMAGE=$(docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=dbpass -e POSTGRES_USER=user -e POSTGRES_DB=demo --rm --name postgres postgres)
CASSANDRA_IMAGE=$(docker run -d -p 7000:7000 --rm --name cassandra bitnami/cassandra:latest)
function cleanup() {
  echo 'cleaning up docker images..'
  docker kill $PG_IMAGE
  docker kill $CASSANDRA_IMAGE
}
trap cleanup SIGKILL SIGINT EXIT

function login() {
  boundary authenticate password -auth-method-id ampw_1234567890 -login-name $1 -password foofoofoo
}

function list_targets() {
  boundary targets list -scope-id p_1234567890 -format json | jq '.[]["id"]'
}

function strip() {
  echo "$1" | tr -d '"'
}

function connect_nc() {
  id=$(strip $1)
  echo "foo" | boundary connect -exec nc -target-id $id -- {{boundary.ip}} {{boundary.port}}
}

for USR in  "jim" "mike" "todd" "randy" "susmitha" "jeff" "pete" "harold" 
do
  login $USR
  for TGT in $(list_targets); do
    echo "Connecting user $USR to target $TGT and sending foo data..."
    connect_nc $TGT
  done
done
