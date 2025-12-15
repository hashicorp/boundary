#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# This script initializes a postgres database to work with Boundary by spinning up a temporary
# Boundary docker container pointed to the specified database and invoking `boundary database init`.
#
# This script must only output the JSON that comes from `boundary database init` as the output is
# consumed by other scripts.

TEST_CONTAINER_NAME=boundary-script-runner
SOURCE=$(realpath $(dirname ${BASH_SOURCE[0]})) # get directory of this script

docker run \
    --rm \
    --name $TEST_CONTAINER_NAME \
    -e "BOUNDARY_ADDR=$BOUNDARY_ADDR" \
    -e "LOGIN_NAME=$E2E_PASSWORD_ADMIN_LOGIN_NAME" \
    -e "BPASS=$E2E_PASSWORD_ADMIN_PASSWORD" \
    -e "BOUNDARY_TOKEN=$BOUNDARY_TOKEN" \
    -e "WORKER_TOKEN=$WORKER_TOKEN" \
    -e "SKIP_CHOWN=true" \
    --cap-add IPC_LOCK \
    --network $TEST_NETWORK_NAME \
    -v "$SCRIPT:/script.sh" \
    $TEST_BOUNDARY_IMAGE \
    /bin/sh -c /script.sh
