# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1


function vault_write_boundary_policy() {
  (
  cat <<EOF
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

path "sys/leases/revoke" {
  capabilities = ["update"]
}

path "sys/capabilities-self" {
  capabilities = ["update"]
}
EOF
  ) | vault policy write boundary-controller -
}

function create_vault_token() {
  vault token create \
    -format=json \
    -no-default-policy=true \
    -policy="boundary-controller" \
    -orphan=true \
    -period=2m \
    -renewable=true | \
    jq -r '.auth.client_token'
}

function skip_if_no_vault() {
  if [[ -z $VAULT_ADDR ]] || [[ -z $VAULT_TOKEN ]]; then
    skip "vault environment variables \$VAULT_ADDR and \$VAULT_TOKEN not set"
  fi
}
