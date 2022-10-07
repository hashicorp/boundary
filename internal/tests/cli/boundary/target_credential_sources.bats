#!/usr/bin/env bats

load _auth
load _connect
load _targets
load _helpers
load _credential_stores
load _credentials
load _target_credential_sources

export NEW_STORE='test-for-add-credential-sources'
export NEW_CREDENTIAL='first-credential'
export NEW_CREDENTIAL1='second-credential'
export NEW_CREDENTIAL2='third-credential'
export NEW_JSON_CREDENTIAL='json-credential'

@test "boundary/login: can login as admin user" {
  run login $DEFAULT_LOGIN
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

@test "boundary/credentials: can create $NEW_JSON_CREDENTIAL credential in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_json_credential $NEW_JSON_CREDENTIAL $csid '-string-kv username=admin -string-kv password=pass'
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: can add $NEW_CREDENTIAL credential source" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run add_target_brokered_credential_sources $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate only $NEW_CREDENTIAL credential source present" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run validate_credential_sources $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: can add $NEW_JSON_CREDENTIAL credential source" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_JSON_CREDENTIAL $csid)
  run add_target_brokered_credential_sources $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_CREDENTIAL & $NEW_JSON_CREDENTIAL credential source present" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local credup_id=$(credential_id $NEW_CREDENTIAL $csid)
  local credjson_id=$(credential_id $NEW_JSON_CREDENTIAL $csid)
  run validate_credential_sources $DEFAULT_TARGET $credup_id
  echo "$output"
  [ "$status" -eq 0 ]
  run validate_credential_sources $DEFAULT_TARGET $credjson_id
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: cannot add duplicate credential source" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run add_target_brokered_credential_sources $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 1 ]
}

@test "boundary/target: can delete $NEW_CREDENTIAL credential source" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run remove_target_brokered_credential_sources $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_CREDENTIAL credential source removed" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run validate_credential_sources_not_present $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: can delete $NEW_JSON_CREDENTIAL credential source" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_JSON_CREDENTIAL $csid)
  run remove_target_brokered_credential_sources $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_JSON_CREDENTIAL credential source removed" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_JSON_CREDENTIAL $csid)
  run validate_credential_sources_not_present $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/credentials: can create additional credentials in $NEW_STORE store" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  run create_username_password_credential $NEW_CREDENTIAL1 $csid 'username' 'password'
  echo "$output"
  [ "$status" -eq 0 ]

  run create_username_password_credential $NEW_CREDENTIAL2 $csid 'username' 'password'
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: can add multiple credential sources" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  local cid1=$(credential_id $NEW_CREDENTIAL1 $csid)
  local cid2=$(credential_id $NEW_CREDENTIAL2 $csid)
  run add_target_brokered_credential_sources $DEFAULT_TARGET $cid $cid1 $cid2
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate added credential sources present" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  local cid1=$(credential_id $NEW_CREDENTIAL1 $csid)
  local cid2=$(credential_id $NEW_CREDENTIAL2 $csid)
  run validate_credential_sources $DEFAULT_TARGET $cid $cid1 $cid2
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: can delete multiple credential sources" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  local cid1=$(credential_id $NEW_CREDENTIAL1 $csid)
  run remove_target_brokered_credential_sources $DEFAULT_TARGET $cid $cid1
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_CREDENTIAL2 credential source present" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid2=$(credential_id $NEW_CREDENTIAL2 $csid)
  run validate_credential_sources $DEFAULT_TARGET $cid2
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate deleted credential sources not present" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  local cid1=$(credential_id $NEW_CREDENTIAL $csid)
  run validate_credential_sources_not_present $DEFAULT_TARGET $cid $cid1
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: can set multiple credential sources" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  local cid1=$(credential_id $NEW_CREDENTIAL1 $csid)
  local cid2=$(credential_id $NEW_CREDENTIAL2 $csid)
  run set_target_brokered_credential_sources $DEFAULT_TARGET $cid $cid1 $cid2
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate set credential sources present" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  local cid1=$(credential_id $NEW_CREDENTIAL1 $csid)
  local cid2=$(credential_id $NEW_CREDENTIAL2 $csid)
  run validate_credential_sources $DEFAULT_TARGET $cid2
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: can set just $NEW_CREDENTIAL credential source" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run set_target_brokered_credential_sources $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_CREDENTIAL credential source present" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid=$(credential_id $NEW_CREDENTIAL $csid)
  run validate_credential_sources $DEFAULT_TARGET $cid
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "boundary/target: validate not set credential sources not present" {
  local csid=$(credential_store_id $NEW_STORE $DEFAULT_P_ID)
  local cid1=$(credential_id $NEW_CREDENTIAL1 $csid)
  local cid2=$(credential_id $NEW_CREDENTIAL2 $csid)
  run validate_credential_sources_not_present $DEFAULT_TARGET $cid1 $cid2
  echo "$output"
  [ "$status" -eq 0 ]
}
