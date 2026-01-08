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
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "image_name" {
  description = "Name of Docker Image"
  type        = string
  default     = "docker.mirror.hashicorp.services/linuxserver/openssh-server:latest"
}
variable "network_name" {
  description = "Name of Docker Networks to join"
  type        = list(string)
}
variable "container_name" {
  description = "Name of Docker Container"
  type        = string
  default     = "openssh-server"
}
variable "target_user" {
  description = "SSH username for target"
  type        = string
  default     = "ubuntu"
}
variable "private_key_file_path" {
  description = "Local Path to key used to SSH onto created hosts"
  type        = string
}

data "tls_public_key" "host_key_openssh" {
  private_key_openssh = file(var.private_key_file_path)
}

locals {
  public_key = data.tls_public_key.host_key_openssh.public_key_openssh
}

resource "docker_image" "openssh_server" {
  name         = var.image_name
  keep_locally = true
}

resource "docker_container" "openssh_server" {
  image = docker_image.openssh_server.image_id
  name  = var.container_name
  env = [
    "PUID=1000",
    "PGID=1000",
    "TZ=US/Eastern",
    "USER_NAME=${var.target_user}",
    "PUBLIC_KEY=${local.public_key}",
  ]
  network_mode = "bridge"
  dynamic "networks_advanced" {
    for_each = var.network_name
    content {
      name = networks_advanced.value
    }
  }
  ports {
    internal = 2222
    external = 2222
  }
  volumes {
    host_path      = format("%s/%s", abspath(path.module), "/custom-cont-init.d")
    container_path = "/custom-cont-init.d"
  }
}

resource "enos_local_exec" "wait" {
  depends_on = [
    docker_container.openssh_server
  ]

  inline = ["timeout 10s bash -c 'until ssh -i ${var.private_key_file_path} -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes ${var.target_user}@localhost; do sleep 2; done'"]
}

output "user" {
  value = var.target_user
}

output "address" {
  value = docker_container.openssh_server.network_data[0].ip_address
}

output "container_name" {
  value = var.container_name
}

output "port" {
  value = "2222"
}
