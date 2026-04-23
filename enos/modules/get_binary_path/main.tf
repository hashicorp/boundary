# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    external = {
      source = "hashicorp/external"
    }
  }
}

variable "name" {
  description = "the binary name"
}

data "external" "find_binary" {
  program = ["bash", "-c", "printf '{\"path\":\"%s\"}' \"$(which ${var.name})\""]
}

output "path" {
  value = dirname(abspath(data.external.find_binary.result.path))
}


