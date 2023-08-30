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
  description = "Path of boundary docker image file to load"
  type        = string
}

resource "enos_local_exec" "load_docker_image" {
  inline = ["docker load -i ${var.path}"]
}
