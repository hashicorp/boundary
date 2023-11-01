# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
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

resource "enos_local_exec" "load_docker_image" {
  inline = ["docker load -i ${var.path}"]
}

output "cli_zip_path" {
  value = var.cli_build_path
}
