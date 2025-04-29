# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "license_path" {}
variable "license" {}

output "license" {
  value = var.license != null ? var.license : file(var.license_path)
}
