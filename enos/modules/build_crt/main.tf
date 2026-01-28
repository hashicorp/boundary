# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# Shim module since CRT provided things will use the crt_bundle_path variable
variable "path" {
  default = "/tmp"
}

variable "build_target" {
  default = "build-ui build"
}

variable "binary_name" {
  default = "boundary"
}

variable "artifact_name" {
  default = "boundary"
}

variable "edition" {
  default = "oss"
}

variable "goos" {
  default = "linux"
}

output "artifact_path" {
  value = var.path
}
