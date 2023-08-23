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
  default     = "boundary"
}
variable "postgres_address" {
  description = "Address to postgres database"
  type        = string
}


resource "docker_image" "boundary" {
  name         = var.image_name
  keep_locally = true
}

resource "enos_local_exec" "init_database" {
  environment = {
    TEST_BOUNDARY_IMAGE   = var.image_name,
    TEST_DATABASE_ADDRESS = var.postgres_address,
    TEST_NETWORK_NAME     = var.network_name
  }
  inline = ["bash ./${path.module}/init.sh"]
}

locals {
  db_init_info   = jsondecode(enos_local_exec.init_database.stdout)
  auth_method_id = local.db_init_info["auth_method"]["auth_method_id"]
  login_name     = local.db_init_info["auth_method"]["login_name"]
  password       = local.db_init_info["auth_method"]["password"]
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
  volumes {
    host_path      = abspath(path.module)
    container_path = "/boundary/"
  }
  healthcheck {
    test     = ["CMD", "wget", "--quiet", "-O", "/dev/null", "http://boundary:9203/health"]
    interval = "3s"
    timeout  = "5s"
    retries  = 5
  }
  wait     = true
  must_run = true
  networks_advanced {
    name = var.network_name
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
  value = "http://0.0.0.0:9200"
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
