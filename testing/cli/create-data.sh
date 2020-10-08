#!/bin/bash
terraform apply

export BOUNDARY_ADDR=http://127.0.0.1:9200

PG_IMAGE=$(docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=dbpass -e POSTGRES_USER=user -e POSTGRES_DB=demo --rm --name postgres postgres)
CASSANDRA_IMAGE=$(docker run -d -p 7000:7000 --rm --name cassandra bitnami/cassandra:latest)
MYSQL_IMAGE=$(docker run --name some-mysql -e MYSQL_ROOT_PASSWORD=my-secret-pw -p 3306:3306 --rm -d mysql)
REDIS_IMAGE=$(docker run -d --rm --name redis -p 6379:6379 redis)
MSSQL_IMAGE=$(docker run --rm --name mssql -e 'ACCEPT_EULA=Y' -e 'SA_PASSWORD=yourStrong(!)Password' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2017-CU8-ubuntu)

function cleanup() {
  echo 'cleaning up docker images..'
  docker kill $PG_IMAGE
  docker kill $CASSANDRA_IMAGE
  docker kill $MYSQL_IMAGE
  docker kill $REDIS_IMAGE
  docker kill $MSSQL_IMAGE
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
