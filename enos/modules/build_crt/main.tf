# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Shim module since CRT provided things will use the crt_bundle_path variable
variable "path" {
  default = "/tmp"
}

output "artifact_path" {
  value = var.path
}
