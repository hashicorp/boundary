#!/usr/bin/env bats

load _auth
load _hosts
load _helpers
load _target_host_sources
load _targets
load _host_catalogs
load _host_sets

export NEW_HOST1='test-for-add-host-source-1'
export NEW_HOST2='test-for-add-host-source-2'
export NEW_HOST_CATALOG='test-host-catalog'
export NEW_HOST_SET1='test-host-set-1'
export NEW_HOST_SET2='test-host-set-2'
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

@test "boundary/hosts: can create multiple hosts in created host catalog" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    run create_host $NEW_HOST1 $hcid
    echo "$output"
    [ "$status" -eq 0 ]

    run create_host $NEW_HOST2 $hcid
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/host-sets: can create add multiple host sets to a created host catalog" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    run create_host_set $hcid $NEW_HOST_SET1
    echo "$output"
    [ "$status" -eq 0 ]

    run create_host_set $hcid $NEW_HOST_SET2
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/host-set/add-host: can associate multiple host sets with created hosts" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hid1=$(host_id $NEW_HOST1 $hcid)
    local hid2=$(host_id $NEW_HOST2 $hcid)
    local hsid1=$(host_set_id $NEW_HOST_SET1 $hcid)
    local hsid2=$(host_set_id $NEW_HOST_SET2 $hcid)

    run assoc_host_set_host $hid1 $hsid1
    echo "$output"
    [ "$status" -eq 0 ]

    run assoc_host_set_host $hid2 $hsid2
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/host-set/add-host: verify all host sets contain created hosts" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hid1=$(host_id $NEW_HOST1 $hcid)
    local hid2=$(host_id $NEW_HOST2 $hcid)
    local hsid1=$(host_set_id $NEW_HOST_SET1 $hcid)
    local hsid2=$(host_set_id $NEW_HOST_SET2 $hcid)

    run host_set_has_host_id $hid1 $hsid1
    echo "$output"
    [ "$status" -eq 0 ]

    run host_set_has_host_id $hid2 $hsid2
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: can set host sources on a created target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid1=$(host_set_id $NEW_HOST_SET1 $hcid)
    local hsid2=$(host_set_id $NEW_HOST_SET2 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run set_target_host_sources $tid $hsid1 $hsid2
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: can remove host sources on a created target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid1=$(host_set_id $NEW_HOST_SET1 $hcid)
    local hsid2=$(host_set_id $NEW_HOST_SET2 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run remove_target_host_sources $tid $hsid1 $hsid2
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: can add created host set to created target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid1=$(host_set_id $NEW_HOST_SET1 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run add_target_host_sources $tid $hsid1
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_HOST1 host source present - JSON" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid=$(host_set_id $NEW_HOST_SET1 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    local format="json"
    run target_has_host_source_id $tid $format $hsid
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_HOST1 host source present - Table" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid=$(host_set_id $NEW_HOST_SET1 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    local format="table"
    run target_has_host_source_id $tid $format $hsid
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: can add another host set to created target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid2=$(host_set_id $NEW_HOST_SET2 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run add_target_host_sources $tid $hsid2
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_HOST2 host source present - Table" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid2=$(host_set_id $NEW_HOST_SET2 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    local format="table"
    run target_has_host_source_id $tid $format $hsid2
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "boundary/target: can remove $NEW_HOST_SET1 host set from created target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid1=$(host_set_id $NEW_HOST_SET1 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run remove_target_host_sources $tid $hsid1
    [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_HOST1 host source is not present on target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid1=$(host_set_id $NEW_HOST_SET1 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    local format="table"
    run target_has_host_source_id $tid $format $hsid1
    echo "$output"
    [ "$status" -eq 1 ]
}

@test "boundary/target: can remove $NEW_HOST_SET2 host set from created target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid2=$(host_set_id $NEW_HOST_SET2 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    run remove_target_host_sources $tid $hsid2
    [ "$status" -eq 0 ]
}

@test "boundary/target: validate $NEW_HOST2 host source is not present on target" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hsid2=$(host_set_id $NEW_HOST_SET2 $hcid)
    local tid=$(target_id_from_name $DEFAULT_P_ID $TGT_NAME)
    local format="json"
    run target_has_host_source_id $tid $format $hsid2
    echo "$output"
    [ "$status" -eq 1 ]
}

@test "boundary/host: can delete all created hosts" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)
    local hid1=$(host_id $NEW_HOST1 $hcid)
    local hid2=$(host_id $NEW_HOST2 $hcid)

    run delete_host $hid1
    echo "$output"
    run has_status_code "$output" "204"
    [ "$status" -eq 0 ]

    run delete_host $hid2
    echo "$output"
    run has_status_code "$output" "204"
    [ "$status" -eq 0 ]
}

@test "boundary/host-set: can delete all created host sets" {
    local hcid=$(host_catalog_id $NEW_HOST_CATALOG $DEFAULT_P_ID)

    local hsid1=$(host_set_id $NEW_HOST_SET1 $hcid)
    run delete_host_set $hsid1
    echo "$output"
    run has_status_code "$output" "204"
    [ "$status" -eq 0 ]

    local hsid2=$(host_set_id $NEW_HOST_SET2 $hcid)
    run delete_host_set $hsid2
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
