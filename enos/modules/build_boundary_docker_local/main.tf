# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "path" {
  description = "File Path of boundary docker image that will be created"
  type        = string
  default     = "/tmp/boundary_docker_image.tar"
}

resource "enos_local_exec" "get_git_sha" {
  inline = ["git rev-parse --short HEAD"]
}

locals {
  image_name = trimspace("docker.io/hashicorp/boundary-dev:latest-${enos_local_exec.get_git_sha.stdout}")
}

resource "enos_local_exec" "build_docker_image" {
  environment = {
    "IMAGE_NAME" = local.image_name
  }
  scripts = ["${path.module}/build.sh"]
}

output "artifact_path" {
  value = var.path
}

output "image_name" {
  value = local.image_name
}
