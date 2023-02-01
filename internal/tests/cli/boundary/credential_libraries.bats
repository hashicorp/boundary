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

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library ecdsa-256" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run update_vault_ssh_certificate_library -id $clid -key-type ecdsa -key-bits 256
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"ecdsa"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "256"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library ecdsa-384" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run update_vault_ssh_certificate_library -id $clid -key-type ecdsa -key-bits 384
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"ecdsa"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "384"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library ecdsa-521" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run update_vault_ssh_certificate_library -id $clid -key-type ecdsa -key-bits 521
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"ecdsa"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "521"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library ecdsa-0" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run update_vault_ssh_certificate_library -id $clid -key-type ecdsa -key-bits 0
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"ecdsa"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "256"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library rsa-2048" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run update_vault_ssh_certificate_library -id $clid -key-type rsa -key-bits 2048
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"rsa"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "2048"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library rsa-3072" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run update_vault_ssh_certificate_library -id $clid -key-type rsa -key-bits 3072
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"rsa"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "3072"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library rsa-4096" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run update_vault_ssh_certificate_library -id $clid -key-type rsa -key-bits 4096
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"rsa"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "4096"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library rsa-0" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run update_vault_ssh_certificate_library -id $clid -key-type rsa -key-bits 0
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"rsa"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "2048"
  [ "$status" -eq 0 ]
}


@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library ed25519" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)
  run update_vault_ssh_certificate_library -id $clid -key-type ed25519 -key-bits null
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"ed25519"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "null"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library key_type default" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)

  # set to something other than the default
  run update_vault_ssh_certificate_library -id $clid -key-type ecdsa -key-bits 384
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"ecdsa"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "384"
  [ "$status" -eq 0 ]

  # now set to the default
  run update_vault_ssh_certificate_library -id $clid -key-type null -key-bits null
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_type" '"ed25519"'
  [ "$status" -eq 0 ]
  run field_eq "$got" ".item.attributes.key_bits" "null"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library ttl" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)

  # can set it
  run update_vault_ssh_certificate_library -id $clid -ttl 1d
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.ttl" '"1d"'
  [ "$status" -eq 0 ]

  # can unset it
  run update_vault_ssh_certificate_library -id $clid -ttl null
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.ttl" "null"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library key_id" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)

  # can set it
  run update_vault_ssh_certificate_library -id $clid -key-id id
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_id" '"id"'
  [ "$status" -eq 0 ]

  # can unset it
  run update_vault_ssh_certificate_library -id $clid -key-id null
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_id" "null"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library extensions" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)

  # can set it
  run update_vault_ssh_certificate_library -id $clid -extension permit-pty
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.extensions" '{"permit-pty":""}'
  [ "$status" -eq 0 ]

  # can set multiple
  run update_vault_ssh_certificate_library -id $clid -extension permit-pty -extension permit-X11-forwarding
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.extensions" '{"permit-X11-forwarding":"","permit-pty":""}'
  [ "$status" -eq 0 ]

  # can unset it
  run update_vault_ssh_certificate_library -id $clid -extensions null
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.extensions" "null"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library critical-options" {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)

  # can set it
  run update_vault_ssh_certificate_library -id $clid -critical-option force-command=/bin/foo
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" '.item.attributes.critical_options["force-command"]' '"/bin/foo"'
  [ "$status" -eq 0 ]

  # can set multiple
  run update_vault_ssh_certificate_library -id $clid -critical-option force-command=/bin/foo -critical-option source-address=10.0.0.1/32
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" '.item.attributes.critical_options["force-command"]' '"/bin/foo"'
  [ "$status" -eq 0 ]
  run field_eq "$got" '.item.attributes.critical_options["source-address"]' '"10.0.0.1/32"'
  [ "$status" -eq 0 ]

  # can unset it
  run update_vault_ssh_certificate_library -id $clid -extensions null
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.extensions" "null"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-libraries: can update $NEW_VAULT_LIB vault-ssh-certificate library " {
  skip_if_no_vault

  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local clid=$(credential_library_id $NEW_VAULT_LIB $csid)

  # can set a ttl
  run update_vault_ssh_certificate_library -id $clid -key-id id
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_id" '"id"'
  [ "$status" -eq 0 ]

  # can unset it
  run update_vault_ssh_certificate_library -id $clid -key-id null
  echo "$output"
  [ "$status" -eq 0 ]

  run read_credential_library $clid
  echo "$output"
  [ "$status" -eq 0 ]
  got=$(echo "$output")

  run field_eq "$got" ".item.attributes.key_id" "null"
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

