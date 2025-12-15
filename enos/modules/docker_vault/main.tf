# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.6.2"
    }

    tls = {
      source  = "hashicorp/tls"
      version = "4.0.4"
    }

    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
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
variable "vault_port" {
  description = "External Port to use"
  type        = string
  default     = "8300"
}
variable "vault_port_internal" {
  description = "Internal Port to use"
  type        = string
  default     = "8300"
}

resource "docker_image" "vault" {
  name         = var.image_name
  keep_locally = true
}

resource "docker_container" "vault" {
  image   = docker_image.vault.image_id
  name    = var.container_name
  command = ["vault", "server", "-config", "/vault/config.d/config.json"]
  ports {
    internal = var.vault_port_internal
    external = var.vault_port
  }
  mounts {
    type   = "bind"
    source = "${abspath(path.module)}/config"
    target = "/vault/config.d"
  }
  capabilities {
    add = ["IPC_LOCK"]
  }
  network_mode = "bridge"
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

resource "enos_local_exec" "init_vault" {
  depends_on = [
    enos_local_exec.check_address
  ]

  environment = {
    VAULT_ADDR        = "http://0.0.0.0:${var.vault_port}"
    VAULT_SKIP_VERIFY = true
  }

  inline = ["vault operator init -format json"]
}

locals {
  vault_init  = jsondecode(enos_local_exec.init_vault.stdout)
  unseal_keys = local.vault_init["unseal_keys_b64"]
  root_token  = local.vault_init["root_token"]
}

resource "enos_local_exec" "unseal_vault" {
  depends_on = [
    enos_local_exec.init_vault
  ]

  environment = {
    VAULT_ADDR        = "http://0.0.0.0:${var.vault_port}"
    VAULT_SKIP_VERIFY = true
  }

  # By default, vault requires 3 keys to unseal
  count = 3
  inline = [
    "vault operator unseal ${local.unseal_keys[count.index]}"
  ]
}

resource "enos_local_exec" "check_health" {
  depends_on = [
    enos_local_exec.init_vault
  ]

  environment = {
    VAULT_ADDR        = "http://0.0.0.0:${var.vault_port}"
    VAULT_TOKEN       = local.root_token
    VAULT_SKIP_VERIFY = true
  }

  inline = ["timeout 10s bash -c 'until vault status; do sleep 2; done'"]
}

output "address_public" {
  value = "http://${var.container_name}:${var.vault_port}"
}

output "address_private" {
  value = "http://${var.container_name}:${var.vault_port_internal}"
}

output "token" {
  value = local.root_token
}

output "port" {
  value = var.vault_port
}
