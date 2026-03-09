# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

disable_mlock = true

controller {
  name        = "controller0"
  description = "A controller"

  database {
    url = "env://LOAD_TEST_BOUNDARY_POSTGRES_URL"
  }

  api_rate_limit {
    resources = ["*"]
    actions   = ["*"]
    per       = "total"
    limit     = 50
    period    = "1m"
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
