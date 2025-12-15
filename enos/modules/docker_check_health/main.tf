# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "container_name" {
  description = "Name of docker container to inspect"
}

resource "enos_local_exec" "check_health" {
  inline = ["timeout 10s bash -c 'until docker inspect ${var.container_name} --format={{.State.Health}} worker | grep {healthy; do sleep 2; done'"]
}
