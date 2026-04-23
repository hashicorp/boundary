# Copyright IBM Corp. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    external = {
      source = "hashicorp/external"
    }
  }
}

data "external" "repo_root" {
  program = ["bash", "-c", "printf '{\"path\":\"%s\"}' \"$(git rev-parse --show-toplevel)\""]
}

output "path" {
  value = abspath(data.external.repo_root.result.path)
}
