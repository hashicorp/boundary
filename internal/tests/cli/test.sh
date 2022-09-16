#!/usr/bin/env bash

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
boundary dev &>/dev/null &
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

until boundary scopes list; do
    echo 'waiting for boundary to be up'
    sleep 1
done

echo "running bats tests"
bats -p ./boundary
