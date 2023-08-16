# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.1"
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
