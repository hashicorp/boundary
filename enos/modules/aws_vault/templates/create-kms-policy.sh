#!/bin/bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

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

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN='${vault_root_token}'

cat > ./kms-transit.hcl << EOF
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

path "transit/encrypt/boundary-recovery" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/boundary-recovery" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/boundary-worker-auth" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/boundary-worker-auth" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/boundary-root" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/boundary-root" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/boundary-bsr" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/boundary-bsr" {
  capabilities = ["create", "update"]
}
EOF

retry 5 ${vault_bin_path} secrets enable transit > /dev/null

retry 5 ${vault_bin_path} policy write boundary-kms-transit-policy ./kms-transit.hcl  > /dev/null

rm ./kms-transit.hcl > /dev/null

retry 5 ${vault_bin_path} token create -policy=boundary-kms-transit-policy -field=token
