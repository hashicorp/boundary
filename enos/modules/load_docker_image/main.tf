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
  description = "Path to Docker image file"
  type        = string
}

resource "enos_local_exec" "load" {
  inline = ["docker load -i ${var.path}"]
}
