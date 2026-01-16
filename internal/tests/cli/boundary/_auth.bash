# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

function login() {
  export BP="${DEFAULT_PASSWORD}"
  boundary authenticate password -auth-method-id $DEFAULT_AMPW -login-name $1 -password env://BP
}


function login_ldap() {
  export BP="${DEFAULT_PASSWORD}"
  boundary authenticate ldap -auth-method-id $DEFAULT_AMPW -login-name $1 -password env://BP
}
