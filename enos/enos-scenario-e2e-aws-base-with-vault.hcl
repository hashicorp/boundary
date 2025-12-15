# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

scenario "e2e_aws_base_with_vault" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  matrix {
    builder = ["local", "crt"]
  }

  locals {
    aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
    boundary_install_dir     = abspath(var.boundary_install_dir)
    license_path             = abspath(var.boundary_license_path != null ? var.boundary_license_path : joinpath(path.root, "./support/boundary.hclic"))
    local_boundary_dir       = var.local_boundary_dir != null ? abspath(var.local_boundary_dir) : null
    build_path = {
      "local" = "/tmp",
      "crt"   = var.crt_bundle_path == null ? null : abspath(var.crt_bundle_path)
    }
    tags = merge({
      "Project Name" : var.project_name
      "Project" : "Enos",
      "Environment" : "ci"
    }, var.tags)
  }

  step "find_azs" {
    module = module.aws_az_finder

    variables {
      instance_type = [
        var.controller_instance_type,
        var.worker_instance_type,
        var.target_instance_type,
        var.vault_instance_type
      ]
    }
  }

  step "read_license" {
    skip_step = var.boundary_edition == "oss"
    module    = module.read_license

    variables {
      license_path = local.license_path
      license      = var.boundary_license
    }
  }

  step "create_db_password" {
    module = module.random_stringifier
  }

  step "build_boundary" {
    module = matrix.builder == "crt" ? module.build_crt : module.build_local

    variables {
      path    = local.build_path[matrix.builder]
      edition = var.boundary_edition
    }
  }

  step "create_base_infra" {
    module = module.aws_vpc
    depends_on = [
      step.find_azs,
    ]

    variables {
      availability_zones = step.find_azs.availability_zones
      common_tags        = local.tags
    }
  }

  step "create_boundary_cluster" {
    module = module.aws_boundary
    depends_on = [
      step.create_base_infra,
      step.create_db_password,
      step.build_boundary
    ]

    variables {
      boundary_binary_name     = var.boundary_binary_name
      boundary_install_dir     = local.boundary_install_dir
      boundary_license         = var.boundary_edition != "oss" ? step.read_license.license : null
      common_tags              = local.tags
      controller_instance_type = var.controller_instance_type
      controller_count         = var.controller_count
      db_pass                  = step.create_db_password.string
      kms_key_arn              = step.create_base_infra.kms_key_arn
      local_artifact_path      = step.build_boundary.artifact_path
      ubuntu_ami_id            = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      vpc_id                   = step.create_base_infra.vpc_id
      vpc_tag_module           = step.create_base_infra.vpc_tag_module
      worker_count             = var.worker_count
      worker_instance_type     = var.worker_instance_type
      aws_region               = var.aws_region
    }
  }

  step "create_vault_cluster" {
    module = module.vault
    depends_on = [
      step.create_base_infra,
    ]

    variables {
      deploy            = true
      ami_id            = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      instance_type     = var.vault_instance_type
      instance_count    = 1
      kms_key_arn       = step.create_base_infra.kms_key_arn
      storage_backend   = "raft"
      sg_additional_ips = step.create_boundary_cluster.controller_ips
      unseal_method     = "awskms"
      vault_release = {
        version = var.vault_version
        edition = "oss"
      }
      vpc_id = step.create_base_infra.vpc_id
    }
  }

  step "create_target" {
    module     = module.aws_target
    depends_on = [step.create_base_infra]

    variables {
      ami_id               = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      aws_ssh_keypair_name = var.aws_ssh_keypair_name
      enos_user            = var.enos_user
      instance_type        = var.target_instance_type
      vpc_id               = step.create_base_infra.vpc_id
      target_count         = var.target_count
      subnet_ids           = step.create_boundary_cluster.subnet_ids
    }
  }

  step "run_e2e_test" {
    module = module.test_e2e
    depends_on = [
      step.create_boundary_cluster,
      step.create_target,
      step.create_vault_cluster
    ]

    variables {
      test_package             = "github.com/hashicorp/boundary/testing/internal/e2e/tests/base_with_vault"
      debug_no_run             = var.e2e_debug_no_run
      alb_boundary_api_addr    = step.create_boundary_cluster.alb_boundary_api_addr
      auth_method_id           = step.create_boundary_cluster.auth_method_id
      auth_login_name          = step.create_boundary_cluster.auth_login_name
      auth_password            = step.create_boundary_cluster.auth_password
      local_boundary_dir       = local.local_boundary_dir
      aws_ssh_private_key_path = local.aws_ssh_private_key_path
      target_address           = step.create_target.target_private_ips[0]
      target_user              = "ubuntu"
      target_port              = "22"
      vault_addr_public        = step.create_vault_cluster.instance_addresses[0]
      vault_addr_private       = step.create_vault_cluster.instance_addresses[0]
      vault_root_token         = step.create_vault_cluster.vault_root_token
      aws_region               = var.aws_region
      max_page_size            = step.create_boundary_cluster.max_page_size
    }
  }

  output "test_results" {
    value = step.run_e2e_test.test_results
  }

  output "controller_ips" {
    value = step.create_boundary_cluster.controller_ips
  }

  output "worker_ips" {
    value = step.create_boundary_cluster.worker_ips
  }

  output "target_ips" {
    value = step.create_target.target_public_ips
  }

  output "vault_ips" {
    value = step.create_vault_cluster.instance_public_ips
  }
}
