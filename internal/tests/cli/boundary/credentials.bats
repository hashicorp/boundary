#!/usr/bin/env bats

load _auth
load _helpers
load _credential_stores
load _credentials

export NEW_STORE='credentials-test-store'
export NEW_CREDENTIAL='test-up'
export NEW_UPD_CREDENTIAL='test-user-pass-domain'
export NEW_UPD_AT_CREDENTIAL='test-at-user-domain-pass'
export NEW_UPD_SLASH_CREDENTIAL='test-slash-domain-user-pass'
export NEW_UPD_CREDENTIAL_DOMAIN='test-domain-user-plus-domain'
export NEW_JSON_CREDENTIAL='test-json'
export NEW_PASSWORD_CREDENTIAL='test-pass'

@test "boundary/login: can login as default user" {
  run login $DEFAULT_LOGIN
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can create $NEW_STORE static store in default project" {
  run create_static_credential_store $NEW_STORE $DEFAULT_P_ID
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can create $NEW_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_credential $NEW_CREDENTIAL $csid 'username' 'password'
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can create $NEW_UPD_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_domain_credential_with_domain $NEW_UPD_CREDENTIAL $csid 'username' 'password' 'domain'
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can create $NEW_UPD_AT_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_domain_credential $NEW_UPD_AT_CREDENTIAL $csid 'username@domain' 'password'
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can create $NEW_UPD_SLASH_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_domain_credential $NEW_UPD_SLASH_CREDENTIAL $csid 'domain\username' 'password'
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can not create username@domain with domain $NEW_UPD_CREDENTIAL_DOMAIN credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_domain_credential_with_domain $NEW_UPD_CREDENTIAL_DOMAIN $csid 'username@domain' 'password' 'domain2'
  [ "$status" -ne 0 ]
  [[ "$output" == *"Error parsing username and domain"* ]]
}

@test "boundary/credentials: can not create domain/username with domain $NEW_UPD_CREDENTIAL_DOMAIN credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_domain_credential_with_domain $NEW_UPD_CREDENTIAL_DOMAIN $csid 'domain\username' 'password' 'domain2'
  [ "$status" -ne 0 ]
  [[ "$output" == *"Error parsing username and domain"* ]]

}

@test "boundary/credentials: can create $NEW_PASSWORD_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_password_credential $NEW_PASSWORD_CREDENTIAL $csid 'password'
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can not create already created $NEW_PASSWORD_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_password_credential $NEW_PASSWORD_CREDENTIAL $csid 'password'
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credentials: can create $NEW_JSON_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_json_credential $NEW_JSON_CREDENTIAL $csid '-string-kv username=admin -string-kv password=pass'
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can not create already created $NEW_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_credential $NEW_CREDENTIAL $csid 'username' 'password'
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credentials: can not create already created $NEW_UPD_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_domain_credential_with_domain $NEW_UPD_CREDENTIAL $csid 'username' 'password' 'domain'
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credentials: can not create already created $NEW_UPD_AT_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_domain_credential $NEW_UPD_AT_CREDENTIAL $csid 'username@domain' 'password'
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credentials: can not create already created $NEW_UPD_SLASH_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_domain_credential $NEW_UPD_SLASH_CREDENTIAL $csid 'domain\username' 'password'
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credentials: can not create already created $NEW_JSON_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_json_credential $NEW_JSON_CREDENTIAL $csid '-string-kv username=admin -string-kv password=pass'
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credentials: can read $NEW_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can read $NEW_UPD_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_UPD_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can read $NEW_UPD_AT_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_UPD_AT_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can read $NEW_UPD_SLASH_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_UPD_SLASH_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can read $NEW_PASSWORD_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_PASSWORD_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can read $NEW_JSON_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_JSON_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can delete $NEW_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run delete_credential $cid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can delete $NEW_UPD_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_UPD_CREDENTIAL $csid)
  run delete_credential $cid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can delete $NEW_UPD_AT_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_UPD_AT_CREDENTIAL $csid)
  run delete_credential $cid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can delete $NEW_UPD_SLASH_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_UPD_SLASH_CREDENTIAL $csid)
  run delete_credential $cid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can delete $NEW_PASSWORD_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_PASSWORD_CREDENTIAL $csid)
  run delete_credential $cid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can delete $NEW_JSON_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_JSON_CREDENTIAL $csid)
  run delete_credential $cid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can not use object flag with kv flags for json credential" {
  echo "{\"key\":\"value\"}" > cred_json_object
  local object_file_path="file://$(pwd)/cred_json_object"
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
 
  local name='object & kv flag test'
  run create_json_credential $name $csid "-object $object_file_path -kv password=pass"
  echo "$output"
  [ "$status" -eq 1 ]

  local name='object & bool-kv flag test'
  run create_json_credential $name $csid "-object $object_file_path -bool-kv password=true"
  echo "$output"
  [ "$status" -eq 1 ]

  local name='object & num-kv flag test'
  run create_json_credential $name $csid "-object $object_file_path -num-kv password=1234"
  echo "$output"
  [ "$status" -eq 1 ]

  local name='object & string-kv flag test'
  run create_json_credential $name $csid "-object $object_file_path -string-kv password=pass"
  echo "$output"
  [ "$status" -eq 1 ]

  rm cred_json_object
}

@test "boundary/credential-stores: can not read deleted $NEW_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credential-stores: can not read deleted $NEW_UPD_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_UPD_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credential-stores: can not read deleted $NEW_UPD_AT_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_UPD_AT_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credential-stores: can not read deleted $NEW_UPD_SLASH_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_UPD_SLASH_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credential-stores: can not read deleted $NEW_PASSWORD_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_PASSWORD_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/credential-stores: can delete $NEW_STORE static store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run delete_credential_store $csid
  echo "$output"
  run has_status_code "$output" "204"
  [ "$status" -eq 0 ]
}

@test "boundary/credential-stores: can not read deleted $NEW_STORE static store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
	run read_credential_store $csid
  echo "$output"
	[ "$status" -eq 1 ]
}

@test "boundary/credential-stores: can not read deleted $NEW_JSON_CREDENTIAL credential" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_JSON_CREDENTIAL $csid)
  run read_credential $cid
  echo "$output"
  [ "$status" -eq 1 ]
}