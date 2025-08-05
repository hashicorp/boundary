# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

scenario "e2e_aws_windows" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  matrix {
    builder    = ["local", "crt"]
    client     = ["win10", "win11"]
    rdp_server = ["2016", "2019", "2022", "2025"]
  }

  locals {
    aws_ssh_private_key_path  = abspath(var.aws_ssh_private_key_path)
    boundary_install_dir      = abspath(var.boundary_install_dir)
    local_boundary_dir        = var.local_boundary_dir != null ? abspath(var.local_boundary_dir) : null
    local_boundary_src_dir    = var.local_boundary_src_dir != null ? abspath(var.local_boundary_src_dir) : null
    local_boundary_ui_src_dir = var.local_boundary_ui_src_dir != null ? abspath(var.local_boundary_ui_src_dir) : null
    boundary_license_path     = abspath(var.boundary_license_path != null ? var.boundary_license_path : joinpath(path.root, "./support/boundary.hclic"))
 
    build_path = {
      "local" = "/tmp",
      "crt"   = var.crt_bundle_path == null ? null : abspath(var.crt_bundle_path)
    }

    tags = merge({
      "Project Name" : var.project_name
      "Project" : "Enos",
      "Environment" : "ci"
    }, var.tags)

    collocated_tag = "collocated"
  }

  step "find_azs" {
    module = module.aws_az_finder

    variables {
      instance_type = [
        var.worker_instance_type,
        var.controller_instance_type
      ]
    }
  }

  step "read_boundary_license" {
    module = module.read_license

    variables {
      license_path = local.boundary_license_path
    }
  }

  step "create_db_password" {
    module = module.random_stringifier
  }

  step "build_boundary_linux" {
    module = matrix.builder == "crt" ? module.build_crt : module.build_local

    variables {
      path    = local.build_path[matrix.builder]
      edition = var.boundary_edition
    }
  }

  step "build_boundary_windows" {
    module = matrix.builder == "crt" ? module.build_crt : module.build_local

    depends_on = [
      step.build_boundary_linux
    ]

    variables {
      path          = local.build_path[matrix.builder]
      edition       = var.boundary_edition
      goos          = "windows"
      build_target  = "build"
      artifact_name = "boundary_windows"
      binary_name   = "boundary.exe"
    }
  }

  step "create_base_infra" {
    module = module.aws_vpc_ipv6

    depends_on = [
      step.find_azs,
    ]

    variables {
      availability_zones = step.find_azs.availability_zones
      common_tags        = local.tags
    }
  }

  step "create_windows_client" {
    module = module.aws_windows_client

    depends_on = [
      step.create_base_infra,
      step.build_boundary_windows,
    ]

    variables {
      vpc_id                = step.create_base_infra.vpc_id
      client_version        = matrix.client
      boundary_cli_zip_path = step.build_boundary_windows.artifact_path
      boundary_ui_src_path  = local.local_boundary_ui_src_dir
      boundary_src_path     = local.local_boundary_src_dir
    }
  }

  step "create_vault_cluster" {
    module = module.vault
    depends_on = [
      step.create_base_infra,
      step.read_vault_license
    ]

    variables {
      deploy          = true
      ami_id          = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      instance_type   = var.vault_instance_type
      instance_count  = 1
      kms_key_arn     = step.create_base_infra.kms_key_arn
      storage_backend = "raft"
      unseal_method   = "shamir"
      ip_version      = "dual"
      vault_license   = step.read_vault_license.license
      vault_release = {
        version = var.vault_version
        edition = "oss"
      }
      vpc_id = step.create_base_infra.vpc_id
    }
  }

  step "create_boundary_cluster" {
    module = module.aws_boundary
    depends_on = [
      step.create_base_infra,
      step.create_windows_client,
      step.create_db_password,
      step.build_boundary_linux,
      step.create_vault_cluster,
      step.read_boundary_license
    ]

    variables {
      boundary_binary_name        = var.boundary_binary_name
      boundary_install_dir        = local.boundary_install_dir
      boundary_license            = var.boundary_edition != "oss" ? step.read_boundary_license.license : null
      common_tags                 = local.tags
      controller_instance_type    = var.controller_instance_type
      controller_count            = var.controller_count
      db_pass                     = step.create_db_password.string
      kms_key_arn                 = step.create_base_infra.kms_key_arn
      local_artifact_path         = step.build_boundary_linux.artifact_path
      ubuntu_ami_id               = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      vpc_id                      = step.create_base_infra.vpc_id
      worker_count                = var.worker_count
      worker_instance_type        = var.worker_instance_type
      controller_config_file_path = "templates/controller_bsr.hcl"
      worker_config_file_path     = "templates/worker_bsr.hcl"
      vault_address               = step.create_vault_cluster.instance_public_ips[0]
      vault_transit_token         = step.create_vault_cluster.vault_transit_token
      aws_region                  = var.aws_region
      ip_version                  = "dual"
      recording_storage_path      = "/recording"
      alb_sg_additional_ips       = step.create_windows_client.public_ip_list
    }
  }

  step "create_test_id" {
    module = module.random_stringifier
    variables {
      length = 5
    }
  }

  step "iam_setup" {
    module = module.aws_iam_setup
    depends_on = [
      step.create_base_infra,
      step.create_test_id
    ]

    variables {
      test_id    = step.create_test_id.string
      test_email = var.test_email
    }
  }

  step "create_bucket" {
    module = module.aws_bucket
    depends_on = [
      step.create_boundary_cluster,
    ]
    variables {
      cluster_tag = step.create_boundary_cluster.cluster_tag
      user        = step.iam_setup.user_name
      is_user     = true
    }
  }

  step "create_rdp_server" {
    module = module.aws_rdp_server
    depends_on = [
      step.create_base_infra,
    ]

    variables {
      vpc_id         = step.create_base_infra.vpc_id
      server_version = matrix.rdp_server
    }
  }

  step "run_e2e_test" {
    module = module.test_e2e
    depends_on = [
      step.create_boundary_cluster,
      step.create_rdp_server,
      step.create_bucket
    ]

    variables {
      test_package             = ""
      debug_no_run             = true
      alb_boundary_api_addr    = step.create_boundary_cluster.alb_boundary_api_addr
      auth_method_id           = step.create_boundary_cluster.auth_method_id
      auth_login_name          = step.create_boundary_cluster.auth_login_name
      auth_password            = step.create_boundary_cluster.auth_password
      local_boundary_dir       = local.local_boundary_dir
      aws_ssh_private_key_path = local.aws_ssh_private_key_path
      target_user              = "ubuntu"
      target_port              = "22"
      aws_bucket_name          = step.create_bucket.bucket_name
      aws_region               = var.aws_region
      max_page_size            = step.create_boundary_cluster.max_page_size
      target_rdp_address       = step.create_rdp_server.private_ip
      target_rdp_user          = step.create_rdp_server.admin_username
      target_rdp_password      = step.create_rdp_server.password
      client_ip_public         = step.create_windows_client.public_ip
      client_username          = step.create_windows_client.test_username
      client_password          = step.create_windows_client.test_password
      client_ssh_key           = step.create_windows_client.private_key
      client_test_dir          = step.create_windows_client.test_dir
    }
  }

  output "controller_ips" {
    value = step.create_boundary_cluster.controller_ips
  }

  output "worker_ips" {
    value = step.create_boundary_cluster.worker_ips
  }

  output "rdp_target_admin_username" {
    value = step.create_rdp_server.admin_username
  }

  output "rdp_target_admin_password" {
    value = step.create_rdp_server.password
  }

  output "rdp_target_public_dns_address" {
    value = step.create_rdp_server.public_dns_address
  }

  output "rdp_target_private_ip" {
    value = step.create_rdp_server.private_ip
  }

  output "windows_client_public_ip" {
    value = step.create_windows_client.public_ip
  }

  output "windows_client_private_ip" {
    value = step.create_windows_client.private_ip
  }

  output "windows_client_ssh_key" {
    value = step.create_windows_client.private_key
  }

  output "windows_client_password" {
    value = step.create_windows_client.admin_password
  }

  output "windows_client_test_user" {
    value = step.create_windows_client.test_username
  }

  output "windows_client_test_password" {
    value = step.create_windows_client.test_password
  }
}
