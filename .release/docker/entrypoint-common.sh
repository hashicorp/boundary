# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# Common entrypoint logic shared between docker-entrypoint.sh and ubi-docker-entrypoint.sh.
# This file is intended to be sourced, not executed directly.

# If the user is trying to run Boundary directly with some arguments, then
# pass them to Boundary.
if [ "${1:0:1}" = '-' ]; then
    set -- boundary "$@"
fi

# Look for Boundary subcommands.
if [ "$1" = 'server' ]; then
    set -- boundary "$@"
elif boundary --help "$1" 2>&1 | grep -q "boundary $1"; then
    # We can't use the return code to check for the existence of a subcommand,
    # so we have to use grep to look for a pattern in the help output.
    set -- boundary "$@"
fi
