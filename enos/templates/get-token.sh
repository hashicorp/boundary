#!/bin/bash
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

# make sure the ALB is up and passing healthchecks
retry 10 curl -s -o /dev/null ${BOUNDARY_ADDR}

export BP="${PASSWORD}"
${BOUNDARY_PATH}/boundary authenticate password -auth-method-id=${METHOD_ID} -login-name=${LOGIN_NAME} -password=env://BP -token-name=none -format=json -keyring-type=none
