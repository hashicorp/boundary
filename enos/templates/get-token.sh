#!/bin/bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

set -e

function retry {
  local retries=$1
  shift
  local count=0

  until "$@"; do
    exit=$?
    wait=$((2 ** count))
    count=$((count + 1))

    if [ "$count" -lt "$retries" ]; then
      sleep "$wait"
    else
      return "$exit"
    fi
  done

  return 0
}

# make sure boundary is connected to DB (unauthenticated endpoint)
retry 10 ${BOUNDARY_PATH}/boundary auth-methods list > /dev/null

export BP="${PASSWORD}"
${BOUNDARY_PATH}/boundary authenticate password -auth-method-id=${METHOD_ID} -login-name=${LOGIN_NAME} -password=env://BP -token-name=none -format=json -keyring-type=none
