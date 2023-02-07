# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

disable_mlock = true

controller {
  name        = "controller0"
  description = "A controller"

  database {
    url = "env://LOAD_TEST_BOUNDARY_POSTGRES_URL"
  }
}

listener "tcp" {
  address     = "boundary"
  purpose     = "api"
  tls_disable = true
}

listener "tcp" {
  address     = "boundary"
  purpose     = "cluster"
  tls_disable = true
}

listener "tcp" {
  address     = "boundary"
  purpose     = "ops"
  tls_disable = true
}
