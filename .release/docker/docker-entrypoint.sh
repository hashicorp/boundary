#!/usr/bin/dumb-init /bin/sh
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

set -e

# Note above that we run dumb-init as PID 1 in order to reap zombie processes
# as well as forward signals to all processes in its session. Normally, sh
# wouldn't do either of these functions so we'd leak zombies as well as do
# unclean termination of all our sub-processes.

# Prevent core dumps
ulimit -c 0

# If the user is trying to run Boundary directly with some arguments, then
# pass them to Boundary.
if [ "${1:0:1}" = '-' ]; then
    set -- boundary "$@"
fi

if [ "$1" = 'server' ]; then
    shift
    set -- boundary server \
        "$@"
elif boundary --help "$1" 2>&1 | grep -q "boundary $1"; then
    # We can't use the return code to check for the existence of a subcommand, so
    # we have to use grep to look for a pattern in the help output.
    set -- boundary "$@"
fi

# If we are running Boundary, make sure it executes as the proper user.
if [ "$1" = 'boundary' ]; then
    if [ -z "$SKIP_CHOWN" ]; then
        # If the config dir is bind mounted then chown it
        if [ "$(stat -c %u /boundary)" != "$(id -u boundary)" ]; then
            chown -R boundary:boundary /boundary || echo "Could not chown /boundary (may not have appropriate permissions)"
        fi
    fi

    if [ -z "$SKIP_SETCAP" ]; then
        # Allow mlock to avoid swapping Boundary memory to disk
        setcap cap_ipc_lock=+ep $(readlink -f $(which boundary))

        # In the case Boundary has been started in a container without IPC_LOCK privileges
        if ! boundary -version 1>/dev/null 2>/dev/null; then
            >&2 echo "Couldn't start Boundary with IPC_LOCK. Disabling IPC_LOCK, please use --privileged or --cap-add IPC_LOCK"
            setcap cap_ipc_lock=-ep $(readlink -f $(which boundary))
        fi
    fi

    if [ "$(id -u)" = '0' ]; then
      set -- su-exec boundary "$@"
    fi
fi

exec "$@"
