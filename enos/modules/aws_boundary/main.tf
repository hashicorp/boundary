# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_version = ">= 1.1.2"

  required_providers {
    enos = {
      source  = "registry.terraform.io/hashicorp-forge/enos"
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

  network_stack = {
    "4" = {
      ingress_cidr_blocks = flatten([
        formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses),
        join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
        formatlist("%s/32", var.alb_sg_additional_ips),
      ])
      ingress_ipv6_cidr_blocks = [],
      egress_cidr_blocks       = ["0.0.0.0/0"],
      egress_ipv6_cidr_blocks  = [],
      ipv6_address_count       = 0,
      vault_address            = var.vault_address,
    },
    "6" = {
      ingress_cidr_blocks = [],
      ingress_ipv6_cidr_blocks = flatten([
        try([for ip in coalesce(data.enos_environment.localhost.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)], []),
        [data.aws_vpc.infra.ipv6_cidr_block],
        [for ip in var.alb_sg_additional_ipv6_ips : cidrsubnet("${ip}/64", 0, 0)],
      ])
      egress_cidr_blocks      = [],
      egress_ipv6_cidr_blocks = ["::/0"],
      ipv6_address_count      = 1,
      vault_address           = format("[%s]", var.vault_address)
    },
    "dual" = {
      ingress_cidr_blocks = flatten([
        formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses),
        join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
        formatlist("%s/32", var.alb_sg_additional_ips),
      ])
      ingress_ipv6_cidr_blocks = flatten([
        try([for ip in coalesce(data.enos_environment.localhost.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)], []),
        [data.aws_vpc.infra.ipv6_cidr_block],
        [for ip in var.alb_sg_additional_ipv6_ips : cidrsubnet("${ip}/64", 0, 0)],
      ]),
      egress_cidr_blocks      = ["0.0.0.0/0"],
      egress_ipv6_cidr_blocks = ["::/0"],
      ipv6_address_count      = 1,
      vault_address           = try(format("[%s]", var.vault_address), "")
    }
  }
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
