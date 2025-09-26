# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "path" {
  description = "Path of boundary docker image file to load"
  type        = string
}

variable "cli_build_path" {
  description = "Path to cli zip file"
  type        = string
}

variable "edition" {
  default = "oss"
}

locals {
  docker_image_filename      = basename(var.path)
  filename_parts             = split("_", replace(local.docker_image_filename, ".docker.tar", ""))
  arch                       = local.filename_parts[3]
  version_and_commit         = join("_", slice(local.filename_parts, 4, length(local.filename_parts)))
  boundary_docker_image_name = "boundary/default/linux/${local.arch}:${local.version_and_commit}"
}

resource "enos_local_exec" "load_docker_image" {
  inline = [
    "docker load -i ${var.path}",
    "echo `Generated image name: ${local.boundary_docker_image_name}`"
  ]
}

output "cli_zip_path" {
  value = var.cli_build_path
}

output "image_name" {
  value = local.boundary_docker_image_name
}