# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

load _authorized_actions

function add_target_brokered_credential_sources() {
  for i in "${@:2}"
  do
    cred+="-brokered-credential-source $i "
  done

  boundary targets add-credential-sources -id $1 $cred
}

function remove_target_brokered_credential_sources() {
  for i in "${@:2}"
  do
    cred+="-brokered-credential-source $i "
  done

  boundary targets remove-credential-sources -id $1 $cred
}

function set_target_brokered_credential_sources() {
  for i in "${@:2}"
  do
    cred+="-brokered-credential-source $i "
  done

  boundary targets set-credential-sources -id $1 $cred
}

function validate_credential_sources() {
  targetData=$(boundary targets read -id $1 -format json)
  for i in "${@:2}"
  do
    if ! echo "$targetData" | grep -q $i; then
      echo "Credential source id '$i' not found on target"
      echo "$targetData"
      exit 1
    fi
  done
}

function validate_credential_sources_not_present() {
  targetData=$(boundary targets read -id $1 -format json)
  for i in "${@:2}"
  do
    if echo "$targetData" | grep -q $i; then
      echo "Credential source id '$i' unexpectedly found on target"
      echo "$targetData"
      exit 1
    fi
  done
}
