# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "boundary_license_path" {}

variable "vault_license_path" {
  default = null
}

output "boundary_license" {
  value = file(var.boundary_license_path)
}

output "vault_license" {
  value = var.vault_license_path != null ? file(var.vault_license_path) : null
}
