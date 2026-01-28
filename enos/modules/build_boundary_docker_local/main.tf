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
  description = "Used in `build_boundary_docker_crt`. Not used in this module."
  type        = string
  default     = ""
}

variable "cli_build_path" {
  description = "Place to store the built binary"
  type        = string
}

variable "edition" {
  default = "oss"
}

variable "ui_build_override" {
  description = "Override for build for UI automation (oss or ent)"
  type        = string
  default     = ""
}

resource "enos_local_exec" "get_git_sha" {
  inline = ["git rev-parse --short HEAD"]
}

locals {
  image_name = trimspace("docker.io/hashicorp/boundary-dev:latest-${enos_local_exec.get_git_sha.stdout}")
}

resource "enos_local_exec" "build_docker_image" {
  environment = {
    "IMAGE_NAME"        = local.image_name
    "ARTIFACT_PATH"     = var.cli_build_path
    "EDITION"           = var.edition
    "UI_BUILD_OVERRIDE" = var.ui_build_override
  }
  scripts = ["${path.module}/build.sh"]
}

output "image_name" {
  value = local.image_name
}

output "cli_zip_path" {
  value = "${var.cli_build_path}/boundary.zip"
}
