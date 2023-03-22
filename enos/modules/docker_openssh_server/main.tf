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
  }
}

variable "image_name" {
  description = "Name of Docker Image"
  type        = string
  default     = "docker.mirror.hashicorp.services/linuxserver/openssh-server"
}
variable "network_name" {
  description = "Name of Docker Network"
  type        = string
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
  networks_advanced {
    name = var.network_name
  }
}

output "user" {
  value = var.target_user
}

output "address" {
  value = docker_container.openssh_server.network_data[0].ip_address
}

output "port" {
  value = "2222"
}
