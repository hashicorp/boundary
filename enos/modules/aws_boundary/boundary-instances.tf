# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

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

  root_block_device {
    iops        = var.controller_ebs_iops
    volume_size = var.controller_ebs_size
    volume_type = var.controller_ebs_type
    throughput  = var.controller_ebs_throughput
    tags        = local.common_tags
  }

  tags = merge(local.common_tags,
    {
      Name = "${local.name_prefix}-boundary-controller-${count.index}"
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

  root_block_device {
    iops        = var.worker_ebs_iops
    volume_size = var.worker_ebs_size
    volume_type = var.worker_ebs_type
    throughput  = var.worker_ebs_throughput
    tags        = local.common_tags
  }

  tags = merge(local.common_tags,
    {
      Name = "${local.name_prefix}-boundary-worker-${count.index}",
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
      host = aws_instance.controller[tonumber(each.value)].public_ip
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
      host = aws_instance.controller[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_file" "controller_config" {
  depends_on  = [enos_bundle_install.controller]
  destination = "/etc/boundary/boundary.hcl"
  content = templatefile("${path.module}/${var.controller_config_file_path}", {
    id                      = each.value
    dbuser                  = var.db_user,
    dbpass                  = var.db_pass,
    dbhost                  = var.db_host == null ? aws_db_instance.boundary[0].address : var.db_host
    dbport                  = var.db_port
    dbname                  = local.db_name,
    db_max_open_connections = var.db_max_open_connections
    kms_key_id              = data.aws_kms_key.kms_key.id,
    local_ipv4              = aws_instance.controller[tonumber(each.value)].private_ip
    api_port                = var.listener_api_port
    ops_port                = var.listener_ops_port
    cluster_port            = var.listener_cluster_port
    region                  = var.aws_region
    max_page_size           = var.max_page_size
  })
  for_each = toset([for idx in range(var.controller_count) : tostring(idx)])

  transport = {
    ssh = {
      host = aws_instance.controller[tonumber(each.value)].public_ip
    }
  }
}

resource "enos_boundary_init" "controller" {
  count = local.is_restored_db ? 0 : 1 // init not required when we restore from a snapshot

  bin_name    = var.boundary_binary_name
  bin_path    = var.boundary_install_dir
  config_path = "/etc/boundary"
  license     = var.boundary_license

  transport = {
    ssh = {
      host = aws_instance.controller[0].public_ip
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
      host = aws_instance.controller[tonumber(each.value)].public_ip
    }
  }

  depends_on = [
    enos_boundary_init.controller,
    enos_file.controller_config // required in the case where we restore from a db snapshot, since the init resource will not be created
  ]
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
      host = aws_instance.worker[tonumber(each.value)].public_ip
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
      host = aws_instance.worker[tonumber(each.value)].public_ip
    }
  }
}


resource "enos_file" "worker_config" {
  depends_on  = [enos_bundle_install.worker]
  destination = "/etc/boundary/boundary.hcl"
  content = templatefile("${path.module}/${var.worker_config_file_path}", {
    id                     = each.value
    kms_key_id             = data.aws_kms_key.kms_key.id,
    controller_ips         = jsonencode(aws_instance.controller.*.private_ip),
    public_addr            = aws_instance.worker.0.public_ip
    region                 = var.aws_region
    type                   = jsonencode(var.worker_type_tags)
    recording_storage_path = var.recording_storage_path

  })
  for_each = toset([for idx in range(var.worker_count) : tostring(idx)])

  transport = {
    ssh = {
      host = aws_instance.worker[tonumber(each.value)].public_ip
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
      host = aws_instance.worker[tonumber(each.value)].public_ip
    }
  }
}
