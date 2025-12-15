# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

function active_users_last_two_months() {
  boundary billing monthly-active-users -format json
}

function active_users_start_time() {
  boundary billing monthly-active-users -start-time=$1 -format json
}

function active_users_start_time_and_end_time() {
  boundary billing monthly-active-users -start-time=$1 -end-time=$2 -format json
}

function active_users_end_time() {
  boundary billing monthly-active-users -end-time=$1 -format json
}