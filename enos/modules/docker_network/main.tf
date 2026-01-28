# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.6.2"
    }
  }
}

variable "network_name" {
  description = "Name of Docker network"
  type        = string
  default     = "e2e_network"
}

resource "docker_network" "test_network" {
  name = var.network_name
}

output "network_name" {
  value = var.network_name
}
