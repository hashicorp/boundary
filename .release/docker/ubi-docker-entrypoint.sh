#!/bin/sh
# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

set -e

# Prevent core dumps
ulimit -c 0

# Due to OpenShift environment compatibility, we have to allow group write
# access to the Boundary configuration. This requires us to disable the
# stricter file permissions checks.
export BOUNDARY_DISABLE_FILE_PERMISSIONS_CHECK=true

# If the user is trying to run Boundary directly with some arguments, then
# pass them to Boundary.
if [ "${1:0:1}" = '-' ]; then
    set -- boundary "$@"
fi

# Look for Boundary subcommands.
if [ "$1" = 'server' ]; then
    set -- boundary "$@"
elif [ "$1" = 'version' ]; then
    set -- boundary "$@"
elif boundary --help "$1" 2>&1 | grep -q "boundary $1"; then
    # We can't use the return code to check for the existence of a subcommand,
    # so we have to use grep to look for a pattern in the help output.
    set -- boundary "$@"
fi

# If we are running Boundary and the container user is root, re-execute as
# the boundary user.
if [ "$1" = 'boundary' ]; then
    if [ "$(id -u)" = '0' ]; then
        export SKIP_CHOWN="true"
        exec su boundary -p -- "$0" "$@"
    fi
fi

exec "$@"
