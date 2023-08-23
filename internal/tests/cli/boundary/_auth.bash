# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

function login() {
  export BP="${DEFAULT_PASSWORD}"
  boundary authenticate password -auth-method-id $DEFAULT_AMPW -login-name $1 -password env://BP
}
