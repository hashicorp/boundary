# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

load _authorized_actions

function add_target_host_sources_sources() {
    for i in "${@:2}"; do
        hostSource+="-host-source $i "
    done

    boundary targets add-host-sources -id $1 $hostSource
}

function remove_target_host_sources_sources() {
    for i in "${@:2}"; do
        hostSource+="-host-source $i "
    done

    boundary targets remove-host-sources -id $1 $hostSource
}

function set_target_host_sources_sources() {
    for i in "${@:2}"; do
        hostSource+="-host-source $i "
    done

    boundary targets set-host-sources -id $1 $hostSource
}

function validate_host_sources() {
    targetData=$(boundary targets read -id $1 -format $3)
    if [[ "$3" == "json" ]]; then
        for i in "${@:2}"; do
            if ! echo "$targetData" | jq ".item.host_sources[]"; then
                echo "Host source id '$i' not found on target"
                echo "$targetData"
                exit 1
            fi
        done
    elif [[ "$3" == "table" ]]; then
        for i in "${@:2}"; do
            pattern="Host Sources:.*ID:.*$2*"
            OUTPUT=$(echo $targetData)
            if ! [[ $OUTPUT =~ $pattern ]]; then
                echo "Host source id '$i' not found on target"
                exit 1
            fi
        done
    fi
}
