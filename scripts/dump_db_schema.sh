#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

die() {
    echo "$@"
    exit 255
}

which pg_dump &> /dev/null || die "pg_dump must be installed"
which pg_isready &> /dev/null || die "pg_isready must be installed"
which make &> /dev/null || die "make must be installed"

set -e

SQL_TEST_DB_PORT=${SQL_TEST_DB_PORT:=5432}
export SQL_TEST_DB_PORT

DB_HOST=${DB_HOST:=127.0.0.1}

dump_wh_tables() {
    local dump="internal/daemon/mcpserver/schema.txt"

    # mkdir -p "${tmp_dir}"

    make -C internal/db/sqltest clean
    make -C internal/db/sqltest database-up
    max=120
    c=0
    until pg_isready -h "${DB_HOST}" -p "${SQL_TEST_DB_PORT}"; do
        ((c+=1))
        if [[ $c -ge $max ]]; then
            docker logs boundary-sql-tests
            make -C internal/db/sqltest clean
            die "timeout waiting for database, likely an error in a migration"
        fi
        sleep 1
    done

    echo "dumping tables beginning with 'wh_' to ${dump}"
    PGPASSWORD=boundary psql -c \d wh_* > schema.txt

    make -C internal/db/sqltest clean
}

echo "Dumping warehouse schema"

dump_wh_tables