# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "container_name" {
  description = "Name of docker container to inspect"
}

resource "enos_local_exec" "check_health" {
  inline = ["timeout 10s bash -c 'until docker inspect ${var.container_name} --format={{.State.Health}} worker | grep {healthy; do sleep 2; done'"]
}
