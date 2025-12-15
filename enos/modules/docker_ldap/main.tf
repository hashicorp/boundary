# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.6.2"
    }

    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "image_name" {
  description = "Name of Docker Image"
  type        = string
  default     = "docker.mirror.hashicorp.services/osixia/openldap:latest"
}
variable "network_name" {
  description = "Name of Docker Networks to join"
  type        = list(string)
}
variable "container_name" {
  description = "Name of Docker Container"
  type        = string
  default     = "ldap"
}

locals {
  user_name      = "einstein"
  user_password  = "password"
  group_name     = "scientists"
  domain         = "example.org"
  domain_dn      = "dc=example,dc=org"
  admin_dn       = "cn=admin,${local.domain_dn}"
  admin_password = "admin"
}

resource "docker_image" "ldap" {
  name         = var.image_name
  keep_locally = true
}

resource "docker_container" "ldap" {
  image = docker_image.ldap.image_id
  name  = var.container_name
  env = [
    "LDAP_DOMAIN=${local.domain}",
    "LDAP_ADMIN_PASSWORD=${local.admin_password}",
  ]
  upload {
    content = templatefile("${abspath(path.module)}/entries/user.ldif", {
      user_name     = local.user_name
      user_password = local.user_password
      domain_dn     = local.domain_dn
    })
    file = "/tmp/ldap/user.ldif"
  }
  upload {
    content = templatefile("${abspath(path.module)}/entries/group.ldif", {
      group_name = local.group_name
      user_name  = local.user_name
      domain_dn  = local.domain_dn
    })
    file = "/tmp/ldap/group.ldif"
  }
  healthcheck {
    test = ["CMD", "ldapsearch", "-H", "ldap://localhost", "-b", "${local.domain_dn}", "-D", "${local.admin_dn}", "-w", "${local.admin_password}"]
  }
  wait         = true
  must_run     = true
  network_mode = "bridge"
  dynamic "networks_advanced" {
    for_each = var.network_name
    content {
      name = networks_advanced.value
    }
  }
}

resource "enos_local_exec" "create_ldap_user" {
  depends_on = [
    docker_container.ldap
  ]

  inline = ["docker exec ${var.container_name} ldapadd -x -H ldap://localhost -D \"${local.admin_dn}\" -w ${local.admin_password} -f /tmp/ldap/user.ldif"]
}

resource "enos_local_exec" "create_ldap_group" {
  depends_on = [
    docker_container.ldap,
    enos_local_exec.create_ldap_user,
  ]

  inline = ["docker exec ${var.container_name} ldapadd -x -H ldap://localhost -D \"${local.admin_dn}\" -w ${local.admin_password} -f /tmp/ldap/group.ldif"]
}

output "address" {
  value = "ldap://${var.container_name}"
}

output "domain_dn" {
  value = local.domain_dn
}

output "admin_dn" {
  value = local.admin_dn
}
output "admin_password" {
  value = local.admin_password
}

output "container_name" {
  value = var.container_name
}

output "user_name" {
  value = local.user_name
}

output "user_password" {
  value = local.user_password
}

output "group_name" {
  value = local.group_name
}
