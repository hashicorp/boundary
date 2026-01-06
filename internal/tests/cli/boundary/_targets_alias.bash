# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

load _authorized_actions

function create_tcp_target_with_alias() {
  local sid=$1
  local port=$2
  local name=$3
  local alias=$4
  boundary targets create tcp \
    -address localhost \
    -default-port $port \
    -name $name \
    -scope-id $sid \
    -with-alias-value $alias \
    -format json
}

function read_target_by_alias() {
  boundary targets read $1 -format json
}

function update_address_by_alias() {
  local aid=$1
  local addr=$2
  boundary targets update tcp $aid -address $2
}

function delete_target_by_alias() {
  boundary targets delete $1 -format json
}

function add_target_host_sources_by_alias() {
    local tid=$1
    local hostSources=${@:2}
    for i in "${hostSources}"; do
        hostSource+="-host-source $i "
    done

    boundary targets add-host-sources $tid $hostSource
}

function target_has_host_source_id_by_alias() {
    local tid=$1
    local format=$2
    local hostSources=${@:3}

    if [[ "$format" == "json" ]]; then
        ids=$(boundary targets read $tid -format json | jq '.item.host_sources[].id')
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
            OUTPUT=$(boundary targets read $tid -format table)
            if ! [[ $OUTPUT =~ $pattern ]]; then
                echo "Host source id '$i' not found on target"
                return 1
            fi
        done
        return 0
    fi
    return 1
}