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
  default = "/tmp"
}

variable "build_target" {
  default = "build-ui build"
}

variable "binary_name" {
  default = "boundary"
}

variable "artifact_name" {
  default = "boundary"
}

variable "edition" {
  default = "oss"
}

variable "goos" {
  default = "linux"
}

variable "ui_build_override" {
  default = null
}

resource "enos_local_exec" "build" {
  environment = {
    "GOOS"          = var.goos,
    "GOARCH"        = "amd64",
    "CGO_ENABLED"   = 0,
    "ARTIFACT_PATH" = var.path
    "ARTIFACT_NAME" = var.artifact_name
    "BINARY_NAME"   = var.binary_name
    "BUILD_TARGET"  = var.build_target
    "EDITION"       = var.edition
    "UI_BUILD_OVERRIDE = var.ui_build_override
  }
  scripts = ["${path.module}/templates/build.sh"]
}

output "artifact_path" {
  value = "${var.path}/${var.artifact_name}.zip"
}
