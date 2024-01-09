# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "name" {
  description = "the binary name"
}

resource "enos_local_exec" "find_binary" {
  inline = ["type -P ${var.name} || (echo \"\n\nCould not find ${var.name} executable. Have you installed it?\n\n\" && exit 1)"]
}

output "path" {
  value = enos_local_exec.find_binary.stdout
}
