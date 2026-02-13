# Copyright (c) HashiCorp, Inc.
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

variable "image_name_server" {
  description = "Name of Docker Image for minio server"
  type        = string
  default     = "docker.mirror.hashicorp.services/minio/minio:latest"
}
variable "image_name_client" {
  description = "Name of Docker Image for minio client"
  type        = string
  default     = "docker.mirror.hashicorp.services/minio/mc:latest"
}
variable "network_name" {
  description = "Name of Docker Networks to join"
  type        = list(string)
}
variable "container_name" {
  description = "Name of Docker Container"
  type        = string
  default     = "minio"
}
variable "region" {
  description = "AWS Region"
  type        = string
  default     = "us-east-1"
}
variable "bucket_name" {
  description = "Name of storage bucket"
  type        = string
  default     = "testbucket" # this needs to match the bucket in policy.json
}
variable "root_user" {
  description = "Username for minio root user"
  type        = string
  default     = "minio"
}
variable "root_password" {
  description = "Password for minio root user"
  type        = string
  default     = "minioadmin"
}
variable "user_id" {
  description = "Username/Access Key Id for user that can access bucket"
  type        = string
  default     = "testuser"
}
variable "user_password" {
  description = "Password/Secret Access Key for user that can access bucket"
  type        = string
  default     = "password"
}
variable "user_access_key_id" {
  description = "Access Key Id for user that can access bucket"
  type        = string
  default     = "useraccesskeyid"
}
variable "user_secret_access_key" {
  description = "Secret Access Key for user that can access bucket"
  type        = string
  default     = "secretaccesskey"
}
variable "minio_alias" {
  description = "Alias used in the minio cli"
  type        = string
  default     = "miniotest"
}

data "docker_registry_image" "minio_server" {
  name = var.image_name_server
}

resource "docker_image" "minio_server" {
  name          = data.docker_registry_image.minio_server.name
  pull_triggers = [data.docker_registry_image.minio_server.sha256_digest]
  keep_locally  = true
}

resource "docker_container" "minio_server" {
  depends_on = [
    docker_image.minio_server
  ]
  image   = docker_image.minio_server.image_id
  name    = var.container_name
  command = ["minio", "server", "/data", "--console-address", ":9090"]
  env = [
    "MINIO_ROOT_USER=minio",
    "MINIO_ROOT_PASSWORD=minioadmin",
    "MINIO_REGION=${var.region}",
  ]
  ports {
    internal = 9000
    external = 9000
  }
  ports {
    internal = 9090
    external = 9090
  }
  healthcheck {
    test     = ["CMD", "mc", "ready", "local"]
    interval = "3s"
    timeout  = "5s"
    retries  = 5
  }
  wait         = true
  network_mode = "bridge"
  dynamic "networks_advanced" {
    for_each = var.network_name
    content {
      name = networks_advanced.value
    }
  }
}

resource "enos_local_exec" "init_minio" {
  depends_on = [
    docker_container.minio_server,
  ]
  environment = {
    MINIO_SERVER_CONTAINER_NAME  = var.container_name,
    MINIO_CLIENT_IMAGE           = var.image_name_client,
    MINIO_BUCKET_NAME            = var.bucket_name,
    MINIO_ROOT_USER              = var.root_user,
    MINIO_ROOT_PASSWORD          = var.root_password,
    MINIO_USER_ID                = var.user_id,
    MINIO_USER_PASSWORD          = var.user_password,
    MINIO_USER_ACCESS_KEY_ID     = var.user_access_key_id,
    MINIO_USER_SECRET_ACCESS_KEY = var.user_secret_access_key,
    TEST_NETWORK_NAME            = var.network_name[0],

  }
  inline = ["bash ./${path.module}/init.sh \"${var.image_name_client}\""]
}

resource "enos_local_exec" "set_alias" {
  depends_on = [enos_local_exec.init_minio]
  environment = {
    MINIO_SERVER_CONTAINER_NAME = var.container_name,
    MINIO_ALIAS                 = var.minio_alias
    MINIO_ROOT_USER             = var.root_user,
    MINIO_ROOT_PASSWORD         = var.root_password,
  }

  inline = [
    "docker exec ${var.container_name} mc alias set ${var.minio_alias} http://localhost:9000 ${var.root_user} ${var.root_password}"
  ]
}

output "bucket_name" {
  value = var.bucket_name
}

output "access_key_id" {
  value = var.user_access_key_id
}

output "secret_access_key" {
  value = var.user_secret_access_key
}

output "bucket_region" {
  value = var.region
}

output "bucket_user_id" {
  value = var.user_id
}

output "endpoint_url" {
  value = "http://${var.container_name}:9000"
}

output "alias" {
  value = var.minio_alias
}
