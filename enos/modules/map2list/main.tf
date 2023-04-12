# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This module was created as a workaround, because we can't currently use
# the `keys()` function call in Enos scenarios

variable "map" {}

output "list" {
  value = keys(var.map)
}
