#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# This script initializes a postgres database to work with Boundary by spinning up a temporary
# Boundary docker container pointed to the specified database and invoking `boundary database init`.
#
# This script must only output the JSON that comes from `boundary database init` as the output is
# consumed by other scripts.

TEST_CONTAINER_NAME=boundary-init
SOURCE=$(realpath $(dirname ${BASH_SOURCE[0]})) # get directory of this script

docker run \
    --rm \
    --name $TEST_CONTAINER_NAME \
    -e "BOUNDARY_POSTGRES_URL=$TEST_DATABASE_ADDRESS" \
    -e "BOUNDARY_LICENSE=$TEST_BOUNDARY_LICENSE" \
    -e "SKIP_CHOWN=true" \
    --cap-add IPC_LOCK \
    -v "$CONFIG:/boundary/boundary-config.hcl" \
    --network $TEST_DATABASE_NETWORK \
    $TEST_BOUNDARY_IMAGE \
    boundary database init -config /boundary/boundary-config.hcl -format json
