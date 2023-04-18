#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

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
    -e "SKIP_CHOWN=true" \
    --cap-add IPC_LOCK \
    --mount type=bind,src=$SOURCE,dst=/boundary/ \
    --network $TEST_NETWORK_NAME \
    $TEST_BOUNDARY_IMAGE \
    boundary database init -config /boundary/boundary-config.hcl -format json
