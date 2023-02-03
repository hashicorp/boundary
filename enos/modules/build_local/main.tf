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
  default = "/tmp"
}

variable "build_target" {
  default = "build-ui build"
}

resource "enos_local_exec" "build" {
  environment = {
    "GOOS"          = "linux",
    "GOARCH"        = "amd64",
    "CGO_ENABLED"   = 0,
    "ARTIFACT_PATH" = var.path
    "BUILD_TARGET"  = var.build_target
  }
  scripts = ["${path.module}/templates/build.sh"]
}

output "artifact_path" {
  value = "${var.path}/boundary.zip"
}
