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
  default = "/tmp"
}

variable "build_target" {
  default = "build-ui build"
}

variable "binary_name" {
  default = "boundary"
}

variable "edition" {
  default = "oss"
}

resource "enos_local_exec" "build" {
  environment = {
    "GOOS"          = "linux",
    "GOARCH"        = "amd64",
    "CGO_ENABLED"   = 0,
    "ARTIFACT_PATH" = var.path
    "BINARY_NAME"   = var.binary_name
    "BUILD_TARGET"  = var.build_target
    "EDITION"       = var.edition
  }
  scripts = ["${path.module}/templates/build.sh"]
}

output "artifact_path" {
  value = "${var.path}/boundary.zip"
}
