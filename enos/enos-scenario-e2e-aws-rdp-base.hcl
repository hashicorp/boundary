# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# This scenario creates a complete end-to-end test environment for Boundary to
# test RDP functionality. It includes a Windows client, a Boundary controller
# and worker, a domain controller, a member server, and another member server
# with a worker running on it.
scenario "e2e_aws_rdp_base" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  matrix {
    builder       = ["local", "crt"]
    client        = ["win10", "win11"]
    kerberos_only = ["true", "false"]
    # Windows Server 2016 does not support OpenSSH, but it's relied on for some
    # parts of setup. If 2016 is selected, the member server will be created as
    # 2016, but the domain controller and worker will be 2019.
    rdp_server = ["2016", "2019", "2022", "2025"]
  }

  locals {
    aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
    boundary_install_dir     = abspath(var.boundary_install_dir)
    local_boundary_dir       = var.local_boundary_dir != null ? abspath(var.local_boundary_dir) : null
    local_boundary_src_dir   = var.local_boundary_src_dir != null ? abspath(var.local_boundary_src_dir) : null
    boundary_license_path    = abspath(var.boundary_license_path != null ? var.boundary_license_path : joinpath(path.root, "./support/boundary.hclic"))
    ip_version               = "4"

    build_path_linux = {
      "local" = "/tmp",
      "crt"   = var.crt_bundle_path == null ? null : abspath(var.crt_bundle_path)
    }

    build_path_windows = {
      "local" = "/tmp",
      "crt"   = var.crt_bundle_path_windows == null ? null : abspath(var.crt_bundle_path_windows)
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

  step "create_base_infra" {
    module = local.ip_version == "4" ? module.aws_vpc : module.aws_vpc_ipv6

    depends_on = [
      step.find_azs,
    ]

    variables {
      availability_zones = step.find_azs.availability_zones
      common_tags        = local.tags
    }
  }

  step "build_boundary_linux" {
    module = matrix.builder == "crt" ? module.build_crt : module.build_local

    variables {
      path    = local.build_path_linux[matrix.builder]
      edition = var.boundary_edition
    }
  }

  step "build_boundary_windows" {
    module = matrix.builder == "crt" ? module.build_crt : module.build_local

    depends_on = [
      step.build_boundary_linux,
    ]

    variables {
      path          = local.build_path_windows[matrix.builder]
      edition       = var.boundary_edition
      goos          = "windows"
      build_target  = "build"
      artifact_name = "boundary_windows"
      binary_name   = "boundary.exe"
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
      boundary_src_path     = local.local_boundary_src_dir
      github_token          = var.github_token
      ip_version            = local.ip_version
      vault_version         = var.vault_version
    }
  }

  step "read_boundary_license" {
    module = module.read_license

    variables {
      license_path = local.boundary_license_path
    }
  }

  step "create_vault_cluster" {
    module = module.vault
    depends_on = [
      step.create_base_infra,
    ]

    variables {
      deploy          = true
      ami_id          = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      instance_type   = var.vault_instance_type
      instance_count  = 1
      kms_key_arn     = step.create_base_infra.kms_key_arn
      storage_backend = "raft"
      unseal_method   = "shamir"
      ip_version      = local.ip_version
      vault_release = {
        version = var.vault_version
        edition = "oss"
      }
      vpc_id = step.create_base_infra.vpc_id
    }
  }

  step "create_db_password" {
    module = module.random_stringifier
  }

  step "create_rdp_domain_controller" {
    module = module.aws_rdp_domain_controller
    depends_on = [
      step.create_base_infra,
    ]

    variables {
      vpc_id         = step.create_base_infra.vpc_id
      server_version = matrix.rdp_server == "2016" ? "2019" : matrix.rdp_server
      ip_version     = local.ip_version
    }
  }

  step "create_boundary_cluster" {
    module = module.aws_boundary
    depends_on = [
      step.create_base_infra,
      step.create_db_password,
      step.build_boundary_linux,
      step.create_windows_client,
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
      ip_version                  = local.ip_version
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

  step "create_windows_worker" {
    module = module.aws_rdp_member_server_with_worker
    depends_on = [
      step.create_base_infra,
      step.create_rdp_domain_controller,
      step.build_boundary_windows,
      step.create_boundary_cluster,
    ]

    variables {
      vpc_id                              = step.create_base_infra.vpc_id
      server_version                      = matrix.rdp_server == "2016" ? "2019" : matrix.rdp_server
      boundary_cli_zip_path               = step.build_boundary_windows.artifact_path
      kms_key_arn                         = step.create_base_infra.kms_key_arn
      controller_ip                       = step.create_boundary_cluster.controller_ips_private
      iam_name                            = step.create_boundary_cluster.iam_instance_profile_name
      boundary_security_group             = step.create_boundary_cluster.boundary_sg_id
      active_directory_domain             = step.create_rdp_domain_controller.domain_name
      domain_controller_aws_keypair_name  = step.create_rdp_domain_controller.keypair_name
      domain_controller_ip                = step.create_rdp_domain_controller.private_ip
      domain_admin_password               = step.create_rdp_domain_controller.password
      domain_controller_private_key       = step.create_rdp_domain_controller.ssh_private_key
      domain_controller_sec_group_id_list = step.create_rdp_domain_controller.security_group_id_list
      aws_region                          = var.aws_region
      ip_version                          = local.ip_version
    }
  }

  step "create_rdp_member_server" {
    module = module.aws_rdp_member_server
    depends_on = [
      step.create_base_infra,
      step.create_rdp_domain_controller,
    ]

    variables {
      vpc_id                              = step.create_base_infra.vpc_id
      server_version                      = matrix.rdp_server
      kerberos_only                       = matrix.kerberos_only == "true" ? true : false
      active_directory_domain             = step.create_rdp_domain_controller.domain_name
      domain_controller_aws_keypair_name  = step.create_rdp_domain_controller.keypair_name
      domain_controller_ip                = step.create_rdp_domain_controller.private_ip
      domain_admin_password               = step.create_rdp_domain_controller.password
      domain_controller_private_key       = step.create_rdp_domain_controller.ssh_private_key
      domain_controller_sec_group_id_list = step.create_rdp_domain_controller.security_group_id_list
      ip_version                          = local.ip_version
    }
  }

  step "run_e2e_test" {
    module = module.test_e2e
    depends_on = [
      step.create_boundary_cluster,
      step.create_rdp_domain_controller,
      step.create_rdp_member_server,
      step.create_windows_worker,
      step.create_bucket
    ]

    variables {
      test_package                             = ""
      debug_no_run                             = true
      alb_boundary_api_addr                    = step.create_boundary_cluster.alb_boundary_api_addr
      auth_method_id                           = step.create_boundary_cluster.auth_method_id
      auth_login_name                          = step.create_boundary_cluster.auth_login_name
      auth_password                            = step.create_boundary_cluster.auth_password
      local_boundary_dir                       = local.local_boundary_dir
      aws_ssh_private_key_path                 = local.aws_ssh_private_key_path
      target_user                              = "ubuntu"
      target_port                              = "22"
      aws_bucket_name                          = step.create_bucket.bucket_name
      aws_region                               = var.aws_region
      max_page_size                            = step.create_boundary_cluster.max_page_size
      worker_tag_collocated                    = local.collocated_tag
      worker_address                           = step.create_windows_worker.public_ip
      target_rdp_domain_controller_addr        = step.create_rdp_domain_controller.private_ip
      target_rdp_domain_controller_addr_ipv6   = local.ip_version == "4" ? "" : step.create_rdp_domain_controller.ipv6[0]
      target_rdp_domain_controller_user        = step.create_rdp_domain_controller.admin_username
      target_rdp_domain_controller_password    = step.create_rdp_domain_controller.password
      target_rdp_domain_controller_ssh_key     = step.create_rdp_domain_controller.ssh_private_key
      target_rdp_member_server_addr            = step.create_rdp_member_server.private_ip
      target_rdp_member_server_domain_hostname = step.create_rdp_member_server.domain_hostname
      target_rdp_member_server_user            = step.create_rdp_member_server.admin_username
      target_rdp_member_server_password        = step.create_rdp_member_server.password
      target_rdp_domain_name                   = step.create_rdp_domain_controller.domain_name
      target_rdp_server_version                = matrix.rdp_server
      controller_ip_public                     = step.create_boundary_cluster.controller_ips[0]
      client_ip_public                         = step.create_windows_client.public_ip
      client_username                          = step.create_windows_client.test_username
      client_password                          = step.create_windows_client.test_password
      client_test_dir                          = step.create_windows_client.test_dir
      client_ssh_key                           = step.create_windows_client.ssh_private_key
      client_version                           = matrix.client
      vault_addr_public                        = step.create_vault_cluster.instance_addresses[0]
      vault_addr_private                       = step.create_vault_cluster.instance_addresses_private[0]
      vault_root_token                         = step.create_vault_cluster.vault_root_token
    }
  }

  output "controller_ips" {
    value = step.create_boundary_cluster.controller_ips
  }

  output "worker_ips" {
    value = step.create_boundary_cluster.worker_ips
  }

  output "rdp_domain_ssh_key" {
    value = step.create_rdp_domain_controller.ssh_private_key
  }

  output "rdp_domain_controller_public_ip" {
    value = step.create_rdp_domain_controller.public_ip
  }

  output "rdp_domain_controller_private_ip" {
    value = step.create_rdp_domain_controller.private_ip
  }

  output "rdp_domain_controller_ipv6" {
    value = step.create_rdp_domain_controller.ipv6
  }

  output "rdp_domain_controller_admin_username" {
    value = step.create_rdp_domain_controller.admin_username
  }

  output "rdp_domain_controller_admin_password" {
    value = step.create_rdp_domain_controller.password
  }

  output "rdp_domain" {
    value = step.create_rdp_domain_controller.domain_name
  }

  output "rdp_member_server_public_ip" {
    value = step.create_rdp_member_server.public_ip
  }

  output "rdp_member_server_private_ip" {
    value = step.create_rdp_member_server.private_ip
  }

  output "rdp_member_server_domain_hostname" {
    value = step.create_rdp_member_server.domain_hostname
  }

  output "rdp_member_server_admin_password" {
    value = step.create_rdp_member_server.password
  }

  output "windows_client_public_ip" {
    value = step.create_windows_client.public_ip
  }

  output "windows_client_private_ip" {
    value = step.create_windows_client.private_ip
  }

  output "windows_client_admin_password" {
    value = step.create_windows_client.admin_password
  }

  output "windows_client_test_user" {
    value = step.create_windows_client.test_username
  }

  output "windows_client_test_password" {
    value = step.create_windows_client.test_password
  }

  output "windows_client_ssh_key" {
    value = step.create_windows_client.ssh_private_key
  }

  output "windows_worker_admin_username" {
    value = step.create_windows_worker.admin_username
  }

  output "windows_worker_admin_password" {
    value = step.create_windows_worker.admin_password
  }

  output "windows_worker_public_ip" {
    value = step.create_windows_worker.public_ip
  }

  output "windows_worker_private_ip" {
    value = step.create_windows_worker.private_ip
  }

  output "vault_address_public" {
    value = step.create_vault_cluster.instance_public_ips_ipv4[0]
  }

  output "vault_root_token" {
    value = step.create_vault_cluster.vault_root_token
  }
}
