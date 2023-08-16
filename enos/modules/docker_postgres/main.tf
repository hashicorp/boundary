# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.1"
    }

    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "image_name" {
  description = "Name of Docker Image"
  type        = string
  default     = "docker.mirror.hashicorp.services/library/postgres:latest"
}
variable "network_name" {
  description = "Name of Docker Network"
  type        = string
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
  volumes {
    host_path      = abspath(path.module)
    container_path = "/etc/postgresql/"
  }
  ports {
    internal = 5432
    external = 5432
  }
  healthcheck {
    test     = ["CMD", "pg_isready", "-U", "${var.user}", "-d", "${var.database_name}"]
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

resource "enos_local_exec" "wait" {
  depends_on = [
    docker_container.postgres
  ]

  inline = ["timeout 10s bash -c 'until docker exec ${var.container_name} pg_isready; do sleep 2; done'"]
}

output "address" {
  value = "postgres://${var.user}:${var.password}@${var.container_name}:5432/${var.database_name}?sslmode=disable"
}
