# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "license_path" {}

output "license" {
  value = file(var.license_path)
}
