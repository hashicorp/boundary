# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# This module was created as a workaround, because we can't currently use
# the `keys()` function call in Enos scenarios

variable "map" {}

output "list" {
  value = keys(var.map)
}
