# Copyright IBM Corp. 2020, 2026
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

data "tls_public_key" "ssh_auth_key" {
  private_key_openssh = file(var.private_key_file_path)
}

resource "tls_private_key" "ca_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

data "tls_public_key" "ca_key" {
  private_key_openssh = tls_private_key.ca_key.private_key_openssh
}

# host keys are used for host validation in the ssh client, but are not used by the server for authentication
resource "tls_private_key" "host_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

data "tls_public_key" "host_key" {
  private_key_openssh = tls_private_key.host_key.private_key_openssh
}

resource "local_sensitive_file" "ca_key" {
  depends_on = [tls_private_key.ca_key]

  content         = tls_private_key.ca_key.private_key_openssh
  filename        = "${path.root}/.terraform/tmp/ca-key"
  file_permission = "0400"
}

resource "local_sensitive_file" "host_public_key" {
  depends_on = [tls_private_key.host_key]

  content         = data.tls_public_key.host_key.public_key_openssh
  filename        = "${path.root}/.terraform/tmp/host-key.pub"
  file_permission = "0644"
}

data "docker_registry_image" "openssh" {
  name = var.image_name
}

resource "docker_image" "openssh_server" {
  name          = var.image_name
  keep_locally  = true
  pull_triggers = [data.docker_registry_image.openssh.sha256_digest]
}

resource "docker_container" "openssh_server" {
  image = docker_image.openssh_server.image_id
  name  = var.container_name
  env = [
    "PUID=1000",
    "PGID=1000",
    "TZ=US/Eastern",
    "USER_NAME=${var.target_user}",
    "PUBLIC_KEY=${data.tls_public_key.ssh_auth_key.public_key_openssh}",
    "SUDO_ACCESS=true",
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
  upload {
    content_base64 = base64encode(tls_private_key.ca_key.private_key_openssh)
    file           = "/ca/ca-key"
  }
  upload {
    content_base64 = base64encode(data.tls_public_key.ca_key.public_key_openssh)
    file           = "/ca/ca-key.pub"
  }
  upload {
    content_base64 = base64encode(tls_private_key.host_key.private_key_openssh)
    file           = "/etc/ssh/host-key"
  }
  upload {
    content_base64 = base64encode(data.tls_public_key.host_key.public_key_openssh)
    file           = "/etc/ssh/host-key.pub"
  }
}

resource "enos_local_exec" "wait" {
  depends_on = [
    docker_container.openssh_server
  ]

  inline = ["timeout 60s bash -c 'until ssh -t -t -i ${var.private_key_file_path} -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes ${var.target_user}@localhost hostname; do sleep 2; done'"]
}

# this host key needs to be created after the container is created
resource "enos_local_exec" "sign_host_key" {
  depends_on = [
    local_sensitive_file.ca_key,
    local_sensitive_file.host_public_key
  ]

  inline = ["ssh-keygen -s ${local_sensitive_file.ca_key.filename} -I host-key -h -n ${docker_container.openssh_server.network_data[0].ip_address},${var.container_name} -V +52w ${local_sensitive_file.host_public_key.filename}"]
}

locals {
  signed_host_key_path = "${trimsuffix(local_sensitive_file.host_public_key.filename, ".pub")}-cert.pub"
}

data "local_file" "signed_host_key" {
  depends_on = [enos_local_exec.sign_host_key]
  filename   = local.signed_host_key_path
}

resource "enos_local_exec" "copy_signed_host_key" {
  depends_on = [data.local_file.signed_host_key]

  inline = ["docker cp ${data.local_file.signed_host_key.filename} ${var.container_name}:/etc/ssh/host-key-cert.pub"]
}

resource "enos_local_exec" "restart_container_for_ssh_changes" {
  depends_on = [enos_local_exec.copy_signed_host_key]

  inline = ["docker restart ${var.container_name}"]
}

resource "enos_local_exec" "wait_after_restart" {
  depends_on = [
    enos_local_exec.restart_container_for_ssh_changes
  ]

  inline = ["timeout 60s bash -c 'until ssh -t -t -i ${var.private_key_file_path} -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes ${var.target_user}@localhost hostname; do sleep 2; done'"]
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

output "ca_key_private" {
  value = base64encode(tls_private_key.ca_key.private_key_openssh)
}

output "ca_key_public" {
  value = base64encode(data.tls_public_key.ca_key.public_key_openssh)
}

output "ca_key_public_string" {
  value = data.tls_public_key.ca_key.public_key_openssh
}
