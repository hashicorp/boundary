# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

controller {
  name        = "controller0"
  description = "A controller but duplicated"

  database {
    url = "env://LOAD_TEST_BOUNDARY_POSTGRES_URL"
  }

  api_rate_limit {
    resources = ["*"]
    actions   = ["list"]
    per       = "total"
    limit     = 20
    period    = "1m"
  }
}
