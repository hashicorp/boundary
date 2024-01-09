# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_version = ">= 1.1.2"

  required_providers {
    enos = {
      source  = "app.terraform.io/hashicorp-qti/enos"
      version = ">= 0.3.25"
    }
  }
}

locals {
  name_prefix          = "${var.project_name}-${var.environment}"
  boundary_cluster_tag = "boundary-server-${random_string.cluster_id.result}"

  is_restored_db           = var.db_snapshot_identifier != null
  default_boundary_db_name = "boundary"
  db_name                  = coalesce(var.db_name, local.default_boundary_db_name)
  common_tags = merge(var.common_tags,
    {
      Module = "aws_boundary"
      Pet    = random_pet.default.id
    },
  )
}

resource "random_string" "cluster_id" {
  length  = 8
  lower   = true
  upper   = false
  numeric = false
  special = false
}

resource "random_pet" "default" {
  separator = "_"
}
