# Copyright IBM Corp. 2020, 2025
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

variable "ui_build_override" {
  description = "Override for build for UI automation (oss or ent)"
  type        = string
  default     = ""
}

variable "edition" {
  default = "oss"
}

resource "enos_local_exec" "load_docker_image" {
  inline = ["docker load -i ${var.path}"]
}

locals {
  boundary_docker_image_name = replace(
    element(
      split("\n", trimspace(enos_local_exec.load_docker_image.stdout)),
      -1
    ),
    "Loaded image: ",
    ""
  )
}

output "cli_zip_path" {
  value = var.cli_build_path
}

output "image_name" {
  value = local.boundary_docker_image_name
}
