# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.1"
    }

    tls = {
      source  = "hashicorp/tls"
      version = "4.0.4"
    }

    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "image_name" {
  description = "Name of Docker Image"
  type        = string
}
variable "network_name" {
  description = "Name of Docker Networks to join"
  type        = list(string)
}
variable "container_name" {
  description = "Name of Docker Container"
  type        = string
  default     = "vault"
}
variable "vault_token" {
  description = "Vault Root Token"
  type        = string
  default     = "boundarytok"
}
variable "vault_port" {
  description = "External Port to use"
  type        = string
  default     = "8300"
}

resource "docker_image" "vault" {
  name         = var.image_name
  keep_locally = true
}

resource "docker_container" "vault" {
  image = docker_image.vault.image_id
  name  = var.container_name
  env = [
    "VAULT_DEV_ROOT_TOKEN_ID=${var.vault_token}"
  ]
  ports {
    internal = 8200
    external = var.vault_port
  }
  capabilities {
    add = ["IPC_LOCK"]
  }
  dynamic "networks_advanced" {
    for_each = var.network_name
    content {
      name = networks_advanced.value
    }
  }
}

resource "enos_local_exec" "check_address" {
  depends_on = [
    docker_container.vault
  ]

  inline = ["timeout 10s bash -c 'until curl http://0.0.0.0:${var.vault_port}; do sleep 2; done'"]
}

resource "enos_local_exec" "check_health" {
  depends_on = [
    enos_local_exec.check_address
  ]

  environment = {
    VAULT_ADDR  = "http://0.0.0.0:${var.vault_port}"
    VAULT_TOKEN = var.vault_token
  }

  inline = ["timeout 10s bash -c 'until vault status; do sleep 2; done'"]
}

output "address" {
  value = "0.0.0.0"
}

output "address_internal" {
  value = var.container_name
}

output "token" {
  value = var.vault_token
}

output "port" {
  value = var.vault_port
}
