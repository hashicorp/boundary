#!/usr/bin/env bats

load _auth
load _hosts
load _helpers
load _target_host_sources
load _targets
load _host_catalogs
load _host_sets

export NEW_HOST='test-for-add-host-source'
export NEW_HOST_CATALOG='test-host-catalog'
export NEW_HOST_SET='test-host-set'
export TGT_NAME='test-target'
export TGT_DEFAULT_PORT='22'

@test "boundary/login: can login as admin user" {
    run login $DEFAULT_LOGIN
    [ "$status" -eq 0 ]
}

@test "boundary/target: admin user can create target" {
    run create_tcp_target $DEFAULT_P_ID $TGT_DEFAULT_PORT $TGT_NAME
    echo $output
    [ "$status" -eq 0 ]
}

@test "boundary/host-catalogs: can create $NEW_HOST_CATALOG host catalog in default project scope" {
    run create_host_catalog $NEW_HOST_CATALOG $DEFAULT_P_ID
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/hosts: can create $NEW_HOST host in created host catalog" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    run create_host $NEW_HOST $hcid
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/host-sets: can add $NEW_HOST_SET host set to created host catalog" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    run create_host_set $hcid $NEW_HOST_SET
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/host-set/add-host: can associate $NEW_HOST_SET host set with created host" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hid=$(host_id $NEW_HOST $hcid)
    local hsid=$(host_set_id $NEW_HOST_SET $hcid)
    run assoc_host_set_host $hid $hsid
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/host-set/add-host: $NEW_HOST_SET host set contains created host" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hid=$(host_id $NEW_HOST $hcid)
    local hsid=$(host_set_id $NEW_HOST_SET $hcid)
    run host_set_has_host_id $hid $hsid
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: can add created host set to created target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid=$(host_set_id $NEW_HOST_SET $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run assoc_host_sources $tid $hsid
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: validate only $NEW_HOST host source present - JSON" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid=$(host_set_id $NEW_HOST_SET $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run validate_host_sources $tid $hsid "json"
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: validate only $NEW_HOST host source present - Table" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid=$(host_set_id $NEW_HOST_SET $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run validate_host_sources $tid $hsid "table"
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: can remove $NEW_HOST_SET host set from created target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid=$(host_set_id $NEW_HOST_SET $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run remove_host_sources $tid $hsid
    [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_HOST host source is not present on target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid=$(host_set_id $NEW_HOST_SET $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run validate_host_sources $tid $hsid "table"
    echo "$output"
    [ "$status" -eq 1 ]
}

@test "boundary/host: can delete $NEW_HOST host" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hid=$(host_id $NEW_HOST $hcid)
    run delete_host $hid
    echo "$output"
    run has_status_code "$output" "204"
    [ "$status" -eq 0 ]
}

@test "boundary/host-set: can delete $NEW_HOST_SET host set" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid=$(host_set_id $NEW_HOST_SET $hcid)
    run delete_host_set $hsid
    echo "$output"
    run has_status_code "$output" "204"
    [ "$status" -eq 0 ]
}

@test "boundary/host-catalogs: can delete $NEW_HOST_CATALOG host catalog in default project scope" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    run delete_host_catalog $hcid
    echo "$output"
    run has_status_code "$output" "204"
    [ "$status" -eq 0 ]
}

@test "boundary/target: can delete target" {
    local id=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run delete_target $id
    run has_status_code "$output" "204"
    [ "$status" -eq 0 ]
}
