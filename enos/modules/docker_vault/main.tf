# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

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
  description = "Name of Docker Network"
  type        = string
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
    external = 8200
  }
  capabilities {
    add = ["IPC_LOCK"]
  }
  networks_advanced {
    name = var.network_name
  }
}

resource "enos_local_exec" "check_address" {
  depends_on = [
    docker_container.vault
  ]

  inline = ["timeout 10s bash -c 'until curl http://0.0.0.0:8200; do sleep 2; done'"]
}

resource "enos_local_exec" "check_health" {
  depends_on = [
    enos_local_exec.check_address
  ]

  environment = {
    VAULT_ADDR  = "http://0.0.0.0:8200"
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
