# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

locals {
  consul_bin_path = "${var.consul_install_dir}/consul"
  key_shares = {
    "awskms" = null
    "shamir" = 5
  }
  key_threshold = {
    "awskms" = null
    "shamir" = 3
  }
  followers   = var.deploy ? toset(slice(local.instances, 1, length(local.instances))) : toset([])
  instances   = var.deploy ? [for idx in range(var.instance_count) : tostring(idx)] : []
  leader      = var.deploy ? toset(slice(local.instances, 0, 1)) : toset([])
  name_suffix = "${var.project_name}-${var.environment}"
  recovery_shares = {
    "awskms" = 5
    "shamir" = null
  }
  recovery_threshold = {
    "awskms" = 3
    "shamir" = null
  }
  seal = {
    "awskms" = {
      type = "awskms"
      attributes = {
        kms_key_id = var.kms_key_arn
      }
    }
    "shamir" = {
      type       = "shamir"
      attributes = null
    }
  }
  storage_config = [for idx in local.vault_instances : (var.storage_backend == "raft" ?
    merge(
      {
        node_id = "${var.vault_node_prefix}_${idx}"
      },
      var.storage_backend_addl_config
    ) :
    {
      address = "127.0.0.1:8500"
      path    = "vault"
    })
  ]
  vault_bin_path         = "${var.vault_install_dir}/vault"
  vault_cluster_tag      = coalesce(var.vault_cluster_tag, "vault-server-${random_string.cluster_id.result}")
  vault_instances        = toset(local.instances)
  audit_device_file_path = "/var/log/vault/vault_audit.log"
  vault_service_user     = "vault"
  enable_audit_device    = var.enable_file_audit_device && var.vault_init
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
