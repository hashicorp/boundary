# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

export UPDATE_NAME='update'

function generic_read() {
    boundary read $1 -format json
}

function generic_update_name() {
    local id=$1
    local name=$2
    boundary update $id -name $name
}

function generic_delete() {
    boundary delete $1 -format json
}