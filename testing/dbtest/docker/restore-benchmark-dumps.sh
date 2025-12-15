#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

set -e
shopt -s globstar

for file in $(ls -v /benchmark_dumps/*.dump); do
    echo "Creating template database based on: ${file}"
    db_name="boundary_$(basename ${file} .dump)_template"
    psql -v "ON_ERROR_STOP=1" --username "$POSTGRES_USER" --dbname "${POSTGRES_DB}" -q <<EOSQL
    create database ${db_name} owner ${POSTGRES_USER};
EOSQL
    echo "Restoring ${file} into ${db_name}"
    pg_restore -j $(nproc) --username "${POSTGRES_USER}" --dbname ${db_name} "${file}"
    psql -v "ON_ERROR_STOP=1" --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" -q <<EOSQL
    update pg_database set datistemplate = true, datallowconn = false where datname = '${db_name}';
EOSQL
done
