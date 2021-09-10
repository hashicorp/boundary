#!/usr/bin/env bash
set -e
shopt -s globstar

psql -v "ON_ERROR_STOP=1" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"   -q <<EOSQL
create user postgres superuser login;
create database boundary_template owner $POSTGRES_USER;
EOSQL


psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --no-password --dbname boundary_template -q <<EOSQL
create table boundary_schema_version (
  version bigint primary key,
  dirty  boolean not null
);
EOSQL

version=

# Run migrations in order.
for file in $(ls -v /migrations/**/*.sql); do
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --no-password --dbname boundary_template -f "$file"

    IFS='/'
    read -ra PARTS <<< "$file"
    major="10#${PARTS[2]}"
    IFS='_'
    read -ra MINOR_PARTS <<< "${PARTS[3]}"
    minor="10#${MINOR_PARTS[0]}"
    let version=${major}*1000+${minor}
    IFS=' '
done

echo "setting boundary_schema_version to ${version}";
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --no-password --dbname boundary_template -q <<EOSQL
insert into boundary_schema_version 
  (version, dirty)
values
  (${version}, false);
EOSQL

psql -v "ON_ERROR_STOP=1" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"   -q <<EOSQL
update pg_database set datistemplate = true, datallowconn = false where datname = 'boundary_template';
EOSQL
