#!/bin/bash
export BOUNDARY_ADDR=http://127.0.0.1:9200

PG_IMAGE=$(docker run -d -p 5439:5439 -e POSTGRES_PASSWORD=dbpass -e POSTGRES_USER=user -e POSTGRES_DB=demo --rm --name postgres postgres)
function cleanup() {
  echo 'cleaning up docker images..'
  docker kill $PG_IMAGE
}
trap cleanup SIGKILL SIGINT EXIT

function login() {
  boundary authenticate password -auth-method-id ampw_1234567890 -login-name admin -password password
}

function list_targets() {
  boundary targets list -scope-id p_1234567890 -format json | jq '.[]["id"]'
}

login
