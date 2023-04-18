# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

listener "tcp" {
  purpose = "proxy"
  tls_disable = true
  address = "0.0.0.0"
}

worker {
  # Workers must be able to reach controllers on :9201
  initial_upstreams = ${controller_addresses}

  public_addr = "${public_addr}"

  tags {
    region = ["${region}"]
    type = ${type}
  }

  auth_storage_path = "/boundary/auth_storage"
  controller_generated_activation_token = "${controller_token}"
}
