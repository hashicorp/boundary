# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

load _authorized_actions

function set_target_host_sources() {
    for i in "${@:2}"; do
        hostSource+="-host-source $i "
    done

    boundary targets set-host-sources -id $1 $hostSource
}

function add_target_host_sources() {
    for i in "${@:2}"; do
        hostSource+="-host-source $i "
    done

    boundary targets add-host-sources -id $1 $hostSource
}

function remove_target_host_sources() {
    for i in "${@:2}"; do
        hostSource+="-host-source $i "
    done

    boundary targets remove-host-sources -id $1 $hostSource
}

function target_has_host_source_id() {
    local tid=$1
    ids=$(boundary targets read -id $tid -format json | jq '.item.host_sources[].id')

    if [[ "$2" == "json" ]]; then
        for i in "${@:3}"; do
            local hsid=$i
            for id in $ids; do
                if [ $(strip "$id") == "$hsid" ]; then
                    return 0
                fi
            done
        done
        return 1
    elif [[ "$2" == "table" ]]; then
        for i in "${@:3}"; do
            pattern="Host Sources:.*ID:.*$i*"
            OUTPUT=$(boundary targets read -id $1 -format table)
            if ! [[ $OUTPUT =~ $pattern ]]; then
                echo "Host source id '$i' not found on target"
                exit 1
            fi
        done
    fi
}
