#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

set -e
shopt -s globstar

# Create database to use as template
psql -v "ON_ERROR_STOP=1" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"   -q <<EOSQL
create user postgres superuser login;
create database boundary_template owner $POSTGRES_USER;
EOSQL

apply_migrations() {
    local edition;
    local major;
    local minor;
    local version;
    local old_ifs;
    local d="$1";

    old_ifs=$IFS
    for file in $(ls -v ${d}/postgres/**/*.up.sql); do
        echo "Applying migration: ${file}"
        psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --no-password --dbname boundary_template -f "$file"

        IFS='/'
        read -ra PARTS <<< "$file"
        echo ${PARTS}
        edition="${PARTS[2]}"
        major="10#${PARTS[4]}"
        IFS='_'
        read -ra MINOR_PARTS <<< "${PARTS[5]}"
        minor="10#${MINOR_PARTS[0]}"
        let version=${major}*1000+${minor}
        IFS=$old_ifs
    done
    echo "setting boundary_schema_version for ${edition} to ${version}";
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --no-password --dbname boundary_template -q <<EOSQL
    insert into boundary_schema_version
      (edition, version)
    values
      ('${edition}', ${version});
EOSQL
}

for file in $(ls -v /migrations/base/postgres/*.up.sql); do
    echo "Applying base migration: ${file}"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --no-password --dbname boundary_template -f "$file"
done

if [ -d /migrations/oss ]; then
    # Run oss migrations in order
    apply_migrations "/migrations/oss";
fi

for d in $(find /migrations/ -mindepth 1 -maxdepth 1 -type d -not -name 'oss' -not -name 'base'); do
    apply_migrations $d;
done

# Make database a template and prevent connections.
psql -v "ON_ERROR_STOP=1" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"   -q <<EOSQL
update pg_database set datistemplate = true, datallowconn = false where datname = 'boundary_template';
EOSQL

# Create database from template
if [ -n "$TEST_DATABASE_UP_WITH_OP" ]; then
    psql -v "ON_ERROR_STOP=1" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -q <<EOSQL
    create database op template boundary_template owner ${POSTGRES_USER};
EOSQL
    echo "Created operational database 'op' based on boundary_template"
fi
