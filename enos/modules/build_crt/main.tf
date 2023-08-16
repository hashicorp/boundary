# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Shim module since CRT provided things will use the crt_bundle_path variable
variable "path" {
  default = "/tmp"
}

output "artifact_path" {
  value = var.path
}
