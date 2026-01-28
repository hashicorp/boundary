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
  default     = "docker.mirror.hashicorp.services/library/postgres:latest"
}
variable "network_name" {
  description = "Name of Docker Networks to join"
  type        = list(string)
}
variable "container_name" {
  description = "Name of Docker Container"
  type        = string
  default     = "database"
}
variable "user" {
  description = "Postgres Database username"
  type        = string
  default     = "boundary"
}
variable "password" {
  description = "Postgres Database password"
  type        = string
  default     = "boundary"
}
variable "database_name" {
  description = "Postgres Database name"
  type        = string
  default     = "boundarydb"
}
variable "port" {
  description = "Docker container port to use"
  type        = number
  default     = 5432
}

resource "docker_image" "postgres" {
  name         = var.image_name
  keep_locally = true
}

resource "docker_container" "postgres" {
  image   = docker_image.postgres.image_id
  name    = var.container_name
  command = ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]
  env = [
    "POSTGRES_DB=${var.database_name}",
    "POSTGRES_USER=${var.user}",
    "POSTGRES_PASSWORD=${var.password}",
  ]
  cpu_set = "1-2"
  memory  = 2000
  volumes {
    host_path      = abspath(path.module)
    container_path = "/etc/postgresql/"
  }
  ports {
    internal = var.port
    external = var.port
  }
  healthcheck {
    test     = ["CMD", "pg_isready", "-U", "${var.user}", "-d", "${var.database_name}"]
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

resource "enos_local_exec" "wait" {
  depends_on = [
    docker_container.postgres
  ]

  inline = ["timeout 10s bash -c 'until docker exec ${var.container_name} pg_isready; do sleep 2; done'"]
}

output "address" {
  value = "postgres://${var.user}:${var.password}@${var.container_name}:5432/${var.database_name}?sslmode=disable"
}

output "user" {
  value = var.user
}

output "password" {
  value = var.password
}

output "database_name" {
  value = var.database_name
}

output "port" {
  value = var.port
}

output "container_name" {
  value = var.container_name
}
