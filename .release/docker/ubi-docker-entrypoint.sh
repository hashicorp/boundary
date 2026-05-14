#!/bin/bash
# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

set -e

# Prevent core dumps
ulimit -c 0

# Due to OpenShift environment compatibility, we have to allow group write
# access to the Boundary configuration. This requires us to disable the
# stricter file permissions checks.
export BOUNDARY_DISABLE_FILE_PERMISSIONS_CHECK=true

# shellcheck source=.release/docker/entrypoint-common.sh
. /usr/local/bin/entrypoint-common.sh

# If we are running Boundary and the container user is root, re-execute as
# the boundary user.
if [ "$1" = 'boundary' ]; then
    if [ "$(id -u)" = '0' ]; then
        export SKIP_CHOWN="true"
        exec su boundary -p -- "$0" "$@"
    fi
fi

exec "$@"
