# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

load _authorized_actions

function set_target_host_sources() {
    local tid=$1
    local hostSources=${@:2}
    for i in "${hostSources}"; do
        hostSource+="-host-source $i "
    done

    boundary targets set-host-sources -id $tid $hostSource
}

function add_target_host_sources() {
    local tid=$1
    local hostSources=${@:2}
    for i in "${hostSources}"; do
        hostSource+="-host-source $i "
    done

    boundary targets add-host-sources -id $tid $hostSource
}

function remove_target_host_sources() {
    local tid=$1
    local hostSources=${@:2}
    for i in "${hostSources}"; do
        hostSource+="-host-source $i "
    done

    boundary targets remove-host-sources -id $tid $hostSource
}

function target_has_host_source_id() {
    local tid=$1
    local format=$2
    local hostSources=${@:3}

    if [[ "$format" == "json" ]]; then
        ids=$(boundary targets read -id $tid -format json | jq '.item.host_sources[].id')
        for i in "${hostSources}"; do
            local hsid=$i
            for id in $ids; do
                if [ $(strip "$id") == "$hsid" ]; then
                    return 0
                fi
            done
        done
        return 1
    elif [[ "$format" == "table" ]]; then
        for i in "${hostSources}"; do
            pattern="Host Sources:.*ID:.*$i*"
            OUTPUT=$(boundary targets read -id $tid -format table)
            if ! [[ $OUTPUT =~ $pattern ]]; then
                echo "Host source id '$i' not found on target"
                return 1
            fi
        done
        return 0
    fi
    return 1
}
