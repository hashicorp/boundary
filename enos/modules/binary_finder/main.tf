# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
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
