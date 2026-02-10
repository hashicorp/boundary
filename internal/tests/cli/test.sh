#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1


# TERM isn't set automatically in CI so we need to make sure it's always there.
export TERM=${TERM:=dumb}

function die {
    echo $*
    exit -1
}

# error out early if missing a command
which boundary || die "missing boundary"
which jq       || die "missing jq"
which bats     || die "missing bats"
which nc       || die "missing nc"

echo "starting boundary dev in background"
boundary dev --create-loopback-plugin &>/dev/null &
boundary_pid=$!

function cleanup {
    rv=$?
    echo "stopping boundary dev"
    if [[ -n ${boundary_pid} ]]; then
        kill ${boundary_pid}
    fi
    exit $rv
}

trap cleanup EXIT

max=120
c=0
until boundary scopes list; do
    echo 'waiting for boundary to be up'
    ((c+=1))
    if [[ $c -ge $max ]]; then
        die "timeout waiting for boundary controller to get healthy"
    fi
    sleep 1
done

c=0
until curl -s http://localhost:9203/health\?worker_info\=1 | jq -e '.worker_process_info.upstream_connection_state == "READY"' > /dev/null; do
    echo 'waiting for boundary worker to be up'
    ((c+=1))
    if [[ $c -ge $max ]]; then
        die "timeout waiting for boundary worker to get healthy"
    fi
    sleep 1
done

# Wait a little longer to ensure the worker is fully ready before we start
# running tests. Without this, there were some flaky tests, specifically when
# trying to connect to a target in the alias tests (those are the first to run).
# The worker health check alone was not sufficient during testing, and it was
# not clear what else could be checked to ensure the worker was fully ready.
sleep 10

echo "running bats tests"
bats -p ./boundary
