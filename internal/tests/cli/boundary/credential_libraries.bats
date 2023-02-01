#!/usr/bin/env bats

load _auth
load _helpers
load _vault
load _credential_stores
load _credential_libraries

export NEW_STORE='test_vault'
export NEW_VAULT_LIB="test_vault"

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: setup vault-generic credential store $NEW_STORE in default project" {
  skip_if_no_vault

  vault_write_boundary_policy
  local vault_token=$(create_vault_token)
  run create_vault_credential_store \
    -name $NEW_STORE -scope-id $DEFAULT_P_ID \
    -vault-address $VAULT_ADDR \
    -vault-token $vault_token

  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can create $NEW_VAULT_LIB vault-generic library in credential store $NEW_STORE" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_vault_generic_library \
    -name $NEW_VAULT_LIB -credential-store-id $csid \
    -vault-path /kv/secret \
    -vault-http-method GET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can not create already created $NEW_VAULT_LIB vault-generic libary" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_vault_generic_library \
    -name $NEW_VAULT_LIB -credential-store-id $csid \
    -vault-path /kv/secret \
    -vault-http-method GET
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credential-libraries: can read $NEW_VAULT_LIB vault-generic library" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can delete $NEW_VAULT_LIB vault-generic library" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run delete_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]

  run delete_credential_library $clid
  echo "$output"
  [ "$status" -eq 1 ]
  run has_status_code "$output" "404"
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can create $NEW_VAULT_LIB vault library in credential store $NEW_STORE deprecated subcommand" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_vault_library \
    -name $NEW_VAULT_LIB -credential-store-id $csid \
    -vault-path /kv/secret \
    -vault-http-method GET
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can not create already created $NEW_VAULT_LIB vault libary deprecated subcommand" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_vault_library \
    -name $NEW_VAULT_LIB -credential-store-id $csid \
    -vault-path /kv/secret \
    -vault-http-method GET
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credential-libraries: can read $NEW_VAULT_LIB vault library depcrecated subcommand" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can delete $NEW_VAULT_LIB vault library depcrecated subcommand" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run delete_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can create $NEW_VAULT_LIB vault-ssh-certificate library in credential store $NEW_STORE" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_vault_ssh_certificate_library \
    -name $NEW_VAULT_LIB -credential-store-id $csid \
    -vault-path /ssh/sign/foo \
    -username foo
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can not create already created $NEW_VAULT_LIB vault-ssh-certificate libary" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_vault_ssh_certificate_library \
    -name $NEW_VAULT_LIB -credential-store-id $csid \
    -vault-path /ssh/sign/foo \
    -username foo
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credential-libraries: can read $NEW_VAULT_LIB vault-ssh-certificate library" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can delete $NEW_VAULT_LIB vault-ssh-certificate library" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run delete_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

# Note, deleting the cred store will revoke the vault token
@test "boundary/credential-stores: cleanup can delete $NEW_STORE vault store" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run delete_credential_store $csid
  echo "$output"
  [ "$status" -eq 0 ]
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

