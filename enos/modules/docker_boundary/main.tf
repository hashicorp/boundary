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
variable "database_network" {
  description = "Name of Docker Network that database lives in"
  type        = string
}
variable "container_name" {
  description = "Name of Docker Container"
  type        = string
  default     = "boundary"
}
variable "postgres_address" {
  description = "Address to postgres database"
  type        = string
}
variable "boundary_license" {
  description = "License string"
  type        = string
}
variable "config_file" {
  description = "Path to config file"
  type        = string
  default     = "boundary-config.hcl"
}
variable "worker_tag" {
  description = "Tag to set on worker for use in worker filters"
  type        = string
  default     = "collocated"
}
variable "max_page_size" {
  description = "Max allowed page size for pagination requests"
  type        = number
  default     = 10
}

resource "docker_image" "boundary" {
  name         = var.image_name
  keep_locally = false
}

resource "enos_local_exec" "init_database" {
  environment = {
    TEST_BOUNDARY_IMAGE   = var.image_name
    TEST_DATABASE_ADDRESS = var.postgres_address
    TEST_DATABASE_NETWORK = var.database_network
    TEST_BOUNDARY_LICENSE = var.boundary_license
    CONFIG                = "${abspath(path.module)}/boundary-config-init.hcl"
  }
  inline = ["bash ./${path.module}/init.sh"]
}

locals {
  db_init_info   = jsondecode(enos_local_exec.init_database.stdout)
  auth_method_id = local.db_init_info["auth_method"]["auth_method_id"]
  login_name     = local.db_init_info["auth_method"]["login_name"]
  password       = local.db_init_info["auth_method"]["password"]
  address        = "http://${var.container_name}:9200"
}

resource "docker_container" "boundary" {
  depends_on = [
    enos_local_exec.init_database,
  ]
  image   = docker_image.boundary.image_id
  name    = var.container_name
  command = ["boundary", "server", "-config", "/boundary/boundary-config.hcl"]
  env = [
    "BOUNDARY_POSTGRES_URL=${var.postgres_address}",
    "BOUNDARY_LICENSE=${var.boundary_license}",
    "HOSTNAME=boundary",
    "SKIP_CHOWN=true",
  ]
  ports {
    internal = 9200
    external = 9200
  }
  ports {
    internal = 9201
    external = 9201
  }
  ports {
    internal = 9202
    external = 9202
  }
  ports {
    internal = 9203
    external = 9203
  }
  capabilities {
    add = ["IPC_LOCK"]
  }

  upload {
    content = templatefile("${abspath(path.module)}/${var.config_file}", {
      worker_type_tag = var.worker_tag,
      max_page_size   = var.max_page_size
    })
    file = "/boundary/boundary-config.hcl"
  }
  healthcheck {
    test     = ["CMD", "wget", "--quiet", "-O", "/dev/null", "http://boundary:9203/health"]
    interval = "3s"
    timeout  = "5s"
    retries  = 5
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

resource "enos_local_exec" "check_address" {
  depends_on = [
    docker_container.boundary
  ]

  inline = ["timeout 10s bash -c 'until curl http://0.0.0.0:9200; do sleep 2; done'"]
}

resource "enos_local_exec" "check_health" {
  depends_on = [
    enos_local_exec.check_address
  ]

  inline = ["timeout 10s bash -c 'until curl -i http://0.0.0.0:9203/health; do sleep 2; done'"]
}

output "address" {
  value = local.address
}

output "upstream_address" {
  value = "${var.container_name}:9201"
}

output "auth_method_id" {
  value = local.auth_method_id
}

output "login_name" {
  value = local.login_name
}

output "password" {
  value = local.password
}

output "worker_tag" {
  value = var.worker_tag
}

output "max_page_size" {
  value = var.max_page_size
}

output "container_name" {
  value = var.container_name
}
