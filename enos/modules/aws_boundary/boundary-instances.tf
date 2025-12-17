# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

data "aws_caller_identity" "current" {}

resource "aws_instance" "controller" {
  count         = var.controller_count
  ami           = var.ubuntu_ami_id
  instance_type = var.controller_instance_type
  vpc_security_group_ids = [
    aws_security_group.boundary_sg.id,
    aws_security_group.boundary_aux_sg.id,
  ]
  subnet_id            = tolist(data.aws_subnets.infra.ids)[count.index % length(data.aws_subnets.infra.ids)]
  key_name             = var.ssh_aws_keypair
  iam_instance_profile = aws_iam_instance_profile.boundary_profile.name
  monitoring           = var.controller_monitoring
  ipv6_address_count   = local.network_stack[var.ip_version].ipv6_address_count

  root_block_device {
    iops        = var.controller_ebs_iops
    volume_size = var.controller_ebs_size
    volume_type = var.controller_ebs_type
    throughput  = var.controller_ebs_throughput
    tags        = local.common_tags
    encrypted   = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = merge(local.common_tags,
    {
      Name = "${local.name_prefix}-boundary-controller-${count.index}-${split(":", data.aws_caller_identity.current.user_id)[1]}"
      Type = local.boundary_cluster_tag,
    },
  )
}

resource "aws_instance" "worker" {
  count                  = var.worker_count
  ami                    = var.ubuntu_ami_id
  instance_type          = var.worker_instance_type
  vpc_security_group_ids = [aws_security_group.boundary_sg.id]
  subnet_id              = tolist(data.aws_subnets.infra.ids)[count.index % length(data.aws_subnets.infra.ids)]
  key_name               = var.ssh_aws_keypair
  iam_instance_profile   = aws_iam_instance_profile.boundary_profile.name
  monitoring             = var.worker_monitoring
  ipv6_address_count     = local.network_stack[var.ip_version].ipv6_address_count

  root_block_device {
    iops        = var.worker_ebs_iops
    volume_size = var.worker_ebs_size
    volume_type = var.worker_ebs_type
    throughput  = var.worker_ebs_throughput
    tags        = local.common_tags
    encrypted   = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = merge(local.common_tags,
    {
      Name = "${local.name_prefix}-boundary-worker-${count.index}-${split(":", data.aws_caller_identity.current.user_id)[1]}",
      Type = local.boundary_cluster_tag,
    },
  )
}

resource "enos_bundle_install" "controller" {
  depends_on = [aws_instance.controller]
  for_each   = toset([for idx in range(var.controller_count) : tostring(idx)])

  destination = var.boundary_install_dir
  artifactory = var.boundary_artifactory_release
  path        = var.local_artifact_path
  release     = var.boundary_release == null ? var.boundary_release : merge(var.boundary_release, { product = "boundary", edition = "oss" })

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.controller[tonumber(each.value)].ipv6_addresses[0] : aws_instance.controller[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_remote_exec" "update_path_controller" {
  depends_on = [enos_bundle_install.controller]
  for_each   = toset([for idx in range(var.controller_count) : tostring(idx)])

  environment = {
    BOUNDARY_INSTALL_DIR = var.boundary_install_dir
  }

  scripts = [abspath("${path.module}/scripts/set-up-login-shell-profile.sh")]

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.controller[tonumber(each.value)].ipv6_addresses[0] : aws_instance.controller[tonumber(each.value)].public_ip
    }
  }
}

locals {
  audit_log_directory    = "/var/log/boundary"
  auth_storage_directory = "/var/lib/boundary"
  service_user           = "boundary"
}

resource "enos_file" "controller_config" {
  depends_on  = [enos_bundle_install.controller]
  destination = "/etc/boundary/boundary.hcl"
  content = templatefile("${path.module}/${var.controller_config_file_path}", {
    id                      = each.value
    dbuser                  = var.db_user
    dbpass                  = var.db_pass
    dbhost                  = var.db_host == null ? aws_db_instance.boundary[0].address : var.db_host
    dbport                  = var.db_port
    dbname                  = local.db_name
    db_max_open_connections = var.db_max_open_connections
    kms_key_id              = data.aws_kms_key.kms_key.id
    listener_address        = var.ip_version == "4" ? "0.0.0.0" : "[::]"
    api_port                = var.listener_api_port
    ops_port                = var.listener_ops_port
    cluster_address         = var.ip_version == "4" ? aws_instance.controller[tonumber(each.value)].private_ip : format("[%s]", aws_instance.controller[tonumber(each.value)].ipv6_addresses[0])
    cluster_port            = var.listener_cluster_port
    region                  = var.aws_region
    max_page_size           = var.max_page_size
    audit_log_dir           = local.audit_log_directory
    vault_address           = local.network_stack[var.ip_version].vault_address
    vault_transit_token     = var.vault_transit_token
  })
  for_each = toset([for idx in range(var.controller_count) : tostring(idx)])

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.controller[tonumber(each.value)].ipv6_addresses[0] : aws_instance.controller[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_boundary_init" "controller" {
  count = !local.is_restored_db && var.controller_count > 0 ? 1 : 0 // init not required when we restore from a snapshot

  bin_name    = var.boundary_binary_name
  bin_path    = var.boundary_install_dir
  config_path = "/etc/boundary"
  license     = var.boundary_license

  transport = {
    ssh = {
      host = try(var.ip_version == "6" ? aws_instance.controller[0].ipv6_addresses[0] : aws_instance.controller[0].public_ip, null)
    }
  }

  depends_on = [enos_file.controller_config]
}

resource "enos_boundary_start" "controller_start" {
  for_each = toset([for idx in range(var.controller_count) : tostring(idx)])

  bin_name    = var.boundary_binary_name
  bin_path    = var.boundary_install_dir
  config_path = "/etc/boundary"
  license     = var.boundary_license

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.controller[tonumber(each.value)].ipv6_addresses[0] : aws_instance.controller[tonumber(each.value)].public_ip
    }
  }

  depends_on = [
    enos_boundary_init.controller,
    enos_file.controller_config // required in the case where we restore from a db snapshot, since the init resource will not be created
  ]
}

resource "enos_remote_exec" "create_controller_audit_log_dir" {
  depends_on = [
    enos_boundary_start.controller_start
  ]
  for_each = toset([for idx in range(var.controller_count) : tostring(idx)])

  environment = {
    NEW_DIR      = local.audit_log_directory
    SERVICE_USER = local.service_user
  }

  scripts = [abspath("${path.module}/scripts/create-dir.sh")]

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.controller[tonumber(each.value)].ipv6_addresses[0] : aws_instance.controller[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_bundle_install" "worker" {
  depends_on = [aws_instance.worker]
  for_each   = toset([for idx in range(var.worker_count) : tostring(idx)])

  destination = var.boundary_install_dir

  artifactory = var.boundary_artifactory_release
  path        = var.local_artifact_path
  release     = var.boundary_release == null ? var.boundary_release : merge(var.boundary_release, { product = "boundary", edition = "oss" })

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.worker[tonumber(each.value)].ipv6_addresses[0] : aws_instance.worker[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_remote_exec" "update_path_worker" {
  depends_on = [enos_bundle_install.worker]
  for_each   = toset([for idx in range(var.worker_count) : tostring(idx)])

  environment = {
    BOUNDARY_INSTALL_DIR = var.boundary_install_dir
  }

  scripts = [abspath("${path.module}/scripts/set-up-login-shell-profile.sh")]

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.worker[tonumber(each.value)].ipv6_addresses[0] : aws_instance.worker[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_file" "worker_config" {
  depends_on  = [enos_bundle_install.worker]
  destination = "/etc/boundary/boundary.hcl"
  content = templatefile("${path.module}/${var.worker_config_file_path}", {
    id                      = each.value
    kms_key_id              = data.aws_kms_key.kms_key.id,
    controller_ips          = var.ip_version == "4" ? jsonencode(aws_instance.controller.*.private_ip) : jsonencode(formatlist("[%s]:9201", flatten(aws_instance.controller.*.ipv6_addresses)))
    listener_address        = var.ip_version == "4" ? "0.0.0.0" : "[::]"
    public_address          = var.ip_version == "6" ? format("[%s]", aws_instance.worker[tonumber(each.value)].ipv6_addresses[0]) : aws_instance.worker[tonumber(each.value)].public_ip
    region                  = var.aws_region
    type                    = jsonencode(var.worker_type_tags)
    recording_storage_path  = var.recording_storage_path
    auth_storage_path       = local.auth_storage_directory
    audit_log_dir           = local.audit_log_directory
    hcp_boundary_cluster_id = var.hcp_boundary_cluster_id
    vault_address           = local.network_stack[var.ip_version].vault_address
    vault_transit_token     = var.vault_transit_token
  })
  for_each = toset([for idx in range(var.worker_count) : tostring(idx)])

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.worker[tonumber(each.value)].ipv6_addresses[0] : aws_instance.worker[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_boundary_start" "worker_start" {
  depends_on = [enos_boundary_start.controller_start, enos_file.worker_config]
  for_each   = toset([for idx in range(var.worker_count) : tostring(idx)])

  bin_name               = var.boundary_binary_name
  bin_path               = var.boundary_install_dir
  config_path            = "/etc/boundary"
  license                = var.boundary_license
  recording_storage_path = var.recording_storage_path != "" ? var.recording_storage_path : null

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.worker[tonumber(each.value)].ipv6_addresses[0] : aws_instance.worker[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_remote_exec" "create_worker_audit_log_dir" {
  depends_on = [
    enos_boundary_start.worker_start,
  ]
  for_each = toset([for idx in range(var.worker_count) : tostring(idx)])

  environment = {
    NEW_DIR      = local.audit_log_directory
    SERVICE_USER = local.service_user
  }

  scripts = [abspath("${path.module}/scripts/create-dir.sh")]

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.worker[tonumber(each.value)].ipv6_addresses[0] : aws_instance.worker[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_remote_exec" "create_worker_auth_storage_dir" {
  depends_on = [
    enos_boundary_start.worker_start,
  ]
  for_each = toset([for idx in range(var.worker_count) : tostring(idx)])

  environment = {
    NEW_DIR      = local.auth_storage_directory
    SERVICE_USER = local.service_user
  }

  scripts = [abspath("${path.module}/scripts/create-dir.sh")]

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.worker[tonumber(each.value)].ipv6_addresses[0] : aws_instance.worker[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_remote_exec" "get_worker_token" {
  depends_on = [enos_boundary_start.worker_start]
  for_each   = var.hcp_boundary_cluster_id != "" ? toset([for idx in range(var.worker_count) : tostring(idx)]) : []

  inline = ["timeout 10s bash -c 'set -eo pipefail; until journalctl -u boundary.service | cat | grep \"Worker Auth Registration Request: .*\" | rev | cut -d \" \" -f 1 | rev | xargs; do sleep 2; done'"]
  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.worker[tonumber(each.value)].ipv6_addresses[0] : aws_instance.worker[tonumber(each.value)].public_ip
    }
  }
}
