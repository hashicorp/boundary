# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

variable "length" {
  type    = number
  default = 10
}
resource "random_string" "string" {
  length  = var.length
  lower   = true
  upper   = true
  numeric = true
  special = false
}

output "string" {
  value = random_string.string.result
}
