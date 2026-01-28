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
  default     = "worker"
}
variable "boundary_license" {
  description = "License string"
  type        = string
}
variable "initial_upstream" {
  description = "Address to upstream instance that it communicates to"
  type        = string
}
variable "port" {
  description = "Port to use"
  type        = number
  default     = 9402
}
variable "tags" {
  description = "Tags to set on worker for use in worker filters"
  type        = list(string)
  default     = ["e2e"]
}
variable "config_file" {
  description = "Path to config file"
  type        = string
  default     = "worker-config.hcl"
}
variable "token" {
  description = "Controller generated activation token to initialize worker"
  type        = string
  default     = ""
}
variable "worker_led_registration" {
  description = "Enables worker-led registration flow"
  type        = bool
  default     = false
}

resource "docker_image" "boundary" {
  name         = var.image_name
  keep_locally = true
}

locals {
  recording_storage_path = "/boundary/recordings"
  port_ops               = var.port + 1
}

resource "docker_container" "worker" {
  image   = docker_image.boundary.image_id
  name    = var.container_name
  command = ["boundary", "server", "-config", "/boundary/worker-config.hcl"]
  env = [
    "BOUNDARY_LICENSE=${var.boundary_license}",
    "HOSTNAME=boundary",
    "SKIP_CHOWN=true",
  ]
  ports {
    internal = var.port
    external = var.port
  }
  ports {
    internal = local.port_ops
    external = local.port_ops
  }
  capabilities {
    add = ["IPC_LOCK"]
  }
  tmpfs = {
    (local.recording_storage_path) = "mode=1777"
    "/boundary/logs"               = "mode=1777"
  }
  upload {
    content = templatefile("${abspath(path.module)}/${var.config_file}", {
      worker_name            = var.container_name
      initial_upstream       = var.initial_upstream
      type_tags              = jsonencode(var.tags)
      recording_storage_path = local.recording_storage_path
      port                   = var.port
      port_ops               = local.port_ops
      token                  = var.token
    })
    file = "/boundary/worker-config.hcl"
  }
  healthcheck {
    test     = ["CMD", "grep", "-i", "worker has successfully authenticated", "/boundary/logs/events.log"]
    interval = "3s"
    timeout  = "5s"
    retries  = 5
  }
  wait         = var.worker_led_registration ? false : true
  must_run     = true
  network_mode = "bridge"
  dynamic "networks_advanced" {
    for_each = var.network_name
    content {
      name = networks_advanced.value
    }
  }
}

resource "enos_local_exec" "get_worker_led_token" {
  count = var.worker_led_registration ? 1 : 0
  depends_on = [
    docker_container.worker
  ]

  inline = ["timeout 10s bash -c 'set -eo pipefail; until docker logs ${var.container_name} 2>&1 | grep \"Worker Auth Registration Request: .*\" | cut -f2- -d':' | xargs; do sleep 2; done'"]
}

resource "enos_local_exec" "check_address" {
  count = var.worker_led_registration ? 0 : 1
  depends_on = [
    docker_container.worker
  ]

  inline = ["timeout 10s bash -c 'until echo $(curl -s -i \"http://0.0.0.0:${local.port_ops}/health?worker_info=1\") | grep -i \\\"upstream_connection_state\\\":\\\"READY\\\"; do sleep 2; done'"]
}

output "upstream_address" {
  value = "${var.container_name}:${var.port}"
}

output "worker_led_token" {
  value = var.worker_led_registration ? trimspace(enos_local_exec.get_worker_led_token[0].stdout) : ""
}
