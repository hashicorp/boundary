# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

worker {
  name              = "worker0"
  description       = "A worker"
  address           = "boundary"
  initial_upstreams = ["boundary:9201"]
}

listener "tcp" {
  address     = "boundary"
  purpose     = "proxy"
  tls_disable = true
}
