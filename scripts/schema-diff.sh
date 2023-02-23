#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0


die() {
    echo "$@"
    exit 255
}

which pg_dump &> /dev/null || die "pg_dump must be installed"
which pg_restore &> /dev/null || die "pg_restore must be installed"
which pg_isready &> /dev/null || die "pg_isready must be installed"
which awk &> /dev/null || die "awk must be installed"
which git &> /dev/null || die "git must be installed"
which make &> /dev/null || die "make must be installed"

set -e

SQL_TEST_DB_PORT=${SQL_TEST_DB_PORT:=5432}
export SQL_TEST_DB_PORT

DB_HOST=${DB_HOST:=127.0.0.1}

base_branch=${1}
if [[ -z "${base_branch}" ]]; then
    base_branch="main"
fi
base_commit=$(git rev-parse "${base_branch}")

new_branch=$(git rev-parse --abbrev-ref HEAD)
new_commit=$(git rev-parse HEAD)

tmp_dir=".schema-diff"

extract() {
    local suffix=$1
    local dump="${tmp_dir}/${suffix}.dump"

    mkdir -p \
        "${tmp_dir}/funcs_${suffix}" \
        "${tmp_dir}/tables_${suffix}" \
        "${tmp_dir}/views_${suffix}" \
        "${tmp_dir}/triggers_${suffix}" \
        "${tmp_dir}/indexes_${suffix}"

    echo "extracting function definitions from ${dump}"
    while read -r f; do
        fname="${f%(*}"
        pg_restore -s -O -P "${f}" -f - "${dump}" | tr '[:upper:]' '[:lower:]' > "${tmp_dir}/funcs_${suffix}/${fname}.sql"
    done < <(pg_restore -l "${dump}" -f - | awk '$4 == "FUNCTION" {for(i=6;i<NF;i++) printf $i" "; print ""}')

    echo "extracting table definitions from ${dump}"
    while read -r t; do
        tname="${t%(*}"
        pg_restore -s -O -t "${t}" -f - "${dump}" | tr '[:upper:]' '[:lower:]' > "${tmp_dir}/tables_${suffix}/${tname}.sql"
    done < <(pg_restore -l "${dump}" -f - | awk '$4 == "TABLE" {for(i=6;i<NF;i++) printf $i" "; print ""}')

    echo "extracting view definitions from ${dump}"
    while read -r v; do
        vname="${v%(*}"
        pg_restore -s -O -t "${v}" -f - "${dump}" | tr '[:upper:]' '[:lower:]' > "${tmp_dir}/views_${suffix}/${vname}.sql"
    done < <(pg_restore -l "${dump}" -f - | awk '$4 == "VIEW" {for(i=6;i<NF;i++) printf $i" "; print ""}')

    echo "extracting trigger definitions from ${dump}"
    while read -r t; do
        tname="${t%(*}"
        pg_restore -s -O -T "${t}" -f - "${dump}" | tr '[:upper:]' '[:lower:]' > "${tmp_dir}/triggers_${suffix}/${tname}.sql"
    done < <(pg_restore -l "${dump}" -f - | awk '$4 == "TRIGGER" {for(i=6;i<NF;i++) printf $i" "; print ""}')

    echo "extracting index definitions from ${dump}"
    while read -r d; do
        dname="${d%(*}"
        pg_restore -s -O -I "${d}" -f - "${dump}" | tr '[:upper:]' '[:lower:]' > "${tmp_dir}/indexes_${suffix}/${dname}.sql"
    done < <(pg_restore -l "${dump}" -f - | awk '$4 == "INDEX" {for(i=6;i<NF;i++) printf $i" "; print ""}')
}

dump() {
    local suffix=$1
    local dump="${tmp_dir}/${suffix}.dump"

    mkdir -p "${tmp_dir}"

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

    echo "dumping to ${dump}"
    pg_dump -Fc -h "${DB_HOST}" -U boundary -f "${dump}"

    make -C internal/db/sqltest clean
}

rm -rf "${tmp_dir}"

echo "Comparing schema between ${new_branch}@${new_commit} ${base_branch}@${base_commit}"

dump "${new_commit}"
extract "${new_commit}"

git checkout "${base_commit}"

dump "${base_commit}"
extract "${base_commit}"

if [[ "${new_branch}" == "HEAD" ]]; then
    git checkout "${new_commit}"
else
    git checkout "${new_branch}"
fi

for t in "funcs" "tables" "views" "triggers" "indexes"; do
    git diff --no-index "${tmp_dir}/${t}_${base_commit}" "${tmp_dir}/${t}_${new_commit}" | tee "${tmp_dir}/${t}.diff"
done
