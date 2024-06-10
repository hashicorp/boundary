# Copyright (c) HashiCorp, Inc.
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
  followers   = toset(slice(local.instances, 1, length(local.instances)))
  instances   = [for idx in range(var.instance_count) : tostring(idx)]
  leader      = toset(slice(local.instances, 0, 1))
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
}
