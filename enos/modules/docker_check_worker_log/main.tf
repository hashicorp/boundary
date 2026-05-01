# Copyright IBM Corp. 2020, 2026
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

variable "worker_id" {
  description = "worker id"
  type        = string
}

resource "enos_local_exec" "check_log" {
  inline = ["timeout 10s bash -c 'until docker logs ${var.container_name} 2>&1 | grep \"new control plane connection saved.*${var.worker_id}\"; do sleep 2; done'"]
}
