# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "tag_name" {
  type = string
}
variable "tag_value" {
  type = string
}

locals {
  tag_map    = { "e2e_${var.tag_name}" : var.tag_value }
  tag_string = "tag:e2e_${var.tag_name}=${var.tag_value}"
}

output "tag_map" {
  value = local.tag_map
}

output "tag_string" {
  value = local.tag_string
}
