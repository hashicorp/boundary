# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source  = "registry.terraform.io/hashicorp-forge/enos"
      version = ">= 0.4.2"
    }
  }
}

data "enos_environment" "localhost" {}

resource "random_string" "cluster_id" {
  length  = 8
  lower   = true
  upper   = false
  numeric = false
  special = false
}

locals {
  network_stack = {
    "4" = {
      ingress_cidr_blocks = flatten([
        formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses),
        join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
        formatlist("%s/32", var.sg_additional_ips),
      ])
      ingress_ipv6_cidr_blocks = [],
      egress_cidr_blocks       = ["0.0.0.0/0"],
      egress_ipv6_cidr_blocks  = [],
      ipv6_address_count       = 0,
    },
    "6" = {
      ingress_cidr_blocks = [],
      ingress_ipv6_cidr_blocks = flatten([
        [for ip in coalesce(data.enos_environment.localhost.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
        [data.aws_vpc.infra.ipv6_cidr_block],
        [for ip in var.sg_additional_ipv6_ips : cidrsubnet("${ip}/64", 0, 0)],
      ])
      egress_cidr_blocks      = [],
      egress_ipv6_cidr_blocks = ["::/0"],
      ipv6_address_count      = 1,
    },
    "dual" = {
      ingress_cidr_blocks = flatten([
        formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses),
      ])
      ingress_ipv6_cidr_blocks = flatten([
        [for ip in coalesce(data.enos_environment.localhost.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
        [data.aws_vpc.infra.ipv6_cidr_block],
        [for ip in var.sg_additional_ipv6_ips : cidrsubnet("${ip}/64", 0, 0)],
      ])
      egress_cidr_blocks      = [],
      egress_ipv6_cidr_blocks = ["::/0"],
      ipv6_address_count      = 1,
    }
  }
}
