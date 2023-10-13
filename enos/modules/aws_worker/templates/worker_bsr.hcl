# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

listener "tcp" {
  purpose = "proxy"
  tls_disable = true
  address = "0.0.0.0"
}

worker {
  # Name attr must be unique across workers
  name = "worker-${id}"
  description = "Enos Boundary worker ${id}"

  # Workers must be able to reach controllers on :9201
  initial_upstreams = ${controller_addresses}

  public_addr = "${public_addr}"

  tags {
    region = ["${region}"]
    type = ${type}
  }

  recording_storage_path = "${recording_storage_path}"
}

# must be same key as used on controller config
kms "awskms" {
  purpose    = "worker-auth"
  region     = "${region}"
  kms_key_id = "${kms_key_id}"
}
