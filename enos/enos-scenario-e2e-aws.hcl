# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# This scenario requires access to the boundary team's test AWS account
scenario "e2e_aws" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  matrix {
    builder    = ["local", "crt"]
    ip_version = ["4"]
  }

  locals {
    aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
    boundary_install_dir     = abspath(var.boundary_install_dir)
    local_boundary_dir       = var.local_boundary_dir != null ? abspath(var.local_boundary_dir) : null
    boundary_license_path    = abspath(var.boundary_license_path != null ? var.boundary_license_path : joinpath(path.root, "./support/boundary.hclic"))
    vault_license_path       = abspath(var.vault_license_path != null ? var.vault_license_path : joinpath(path.root, "./support/vault.hclic"))

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
        var.target_instance_type
      ]
    }
  }

  step "read_boundary_license" {
    skip_step = var.boundary_edition == "oss"
    module    = module.read_license

    variables {
      license_path = local.boundary_license_path
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
    module = matrix.ip_version == "4" ? module.aws_vpc : module.aws_vpc_ipv6

    depends_on = [
      step.find_azs,
    ]

    variables {
      availability_zones = step.find_azs.availability_zones
      common_tags        = local.tags
    }
  }

  step "create_vault_cluster" {
    module = module.vault
    depends_on = [
      step.create_base_infra,
    ]

    variables {
      deploy          = matrix.ip_version == "4" ? false : true
      ami_id          = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      instance_type   = var.vault_instance_type
      instance_count  = 1
      kms_key_arn     = step.create_base_infra.kms_key_arn
      storage_backend = "raft"
      unseal_method   = "shamir"
      ip_version      = matrix.ip_version
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
      step.create_db_password,
      step.build_boundary,
      step.create_vault_cluster
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
      local_artifact_path         = step.build_boundary.artifact_path
      ubuntu_ami_id               = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      vpc_id                      = step.create_base_infra.vpc_id
      vpc_tag_module              = step.create_base_infra.vpc_tag_module
      worker_count                = var.worker_count
      worker_instance_type        = var.worker_instance_type
      aws_region                  = var.aws_region
      ip_version                  = matrix.ip_version
      controller_config_file_path = matrix.ip_version == "4" ? "templates/controller.hcl" : "templates/controller_vault_kms.hcl"
      worker_config_file_path     = matrix.ip_version == "4" ? "templates/worker.hcl" : "templates/worker_vault_kms.hcl"
      vault_address               = matrix.ip_version == "4" ? "" : step.create_vault_cluster.instance_public_ips[0]
      vault_transit_token         = matrix.ip_version == "4" ? "" : step.create_vault_cluster.vault_transit_token
    }
  }

  step "create_tag1" {
    module = module.random_stringifier
  }

  step "create_tag1_inputs" {
    module     = module.generate_aws_host_tag_vars
    depends_on = [step.create_tag1]

    variables {
      tag_name  = step.create_tag1.string
      tag_value = "true"
    }
  }

  step "create_targets_with_tag1" {
    module     = module.aws_target
    depends_on = [step.create_base_infra]

    variables {
      ami_id               = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      aws_ssh_keypair_name = var.aws_ssh_keypair_name
      enos_user            = var.enos_user
      instance_type        = var.target_instance_type
      vpc_id               = step.create_base_infra.vpc_id
      target_count         = var.target_count <= 1 ? 2 : var.target_count
      additional_tags      = step.create_tag1_inputs.tag_map
      subnet_ids           = step.create_boundary_cluster.subnet_ids
      ingress_cidr         = matrix.ip_version == "4" ? ["10.0.0.0/8"] : []
      ingress_ipv6_cidr    = step.create_boundary_cluster.worker_ipv6_cidr
      ip_version           = matrix.ip_version
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

  locals {
    isolated_tag = "isolated"
  }

  step "create_isolated_worker" {
    module     = module.aws_worker
    depends_on = [step.create_boundary_cluster]
    variables {
      vpc_id               = step.create_base_infra.vpc_id
      availability_zones   = step.create_base_infra.availability_zone_names
      kms_key_arn          = step.create_base_infra.kms_key_arn
      ubuntu_ami_id        = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      vpc_cidr             = step.create_base_infra.vpc_cidr
      vpc_cidr_ipv6        = matrix.ip_version == "4" ? "" : step.create_base_infra.vpc_cidr_ipv6
      local_artifact_path  = step.build_boundary.artifact_path
      boundary_install_dir = local.boundary_install_dir
      name_prefix          = step.create_boundary_cluster.name_prefix
      cluster_tag          = step.create_boundary_cluster.cluster_tag
      controller_addresses = step.create_boundary_cluster.public_controller_addresses
      controller_sg_id     = step.create_boundary_cluster.controller_aux_sg_id
      worker_type_tags     = [local.isolated_tag]
      ip_version           = matrix.ip_version
      config_file_path     = "templates/worker.hcl"
    }
  }

  step "create_tag2" {
    module = module.random_stringifier
  }

  step "create_tag2_inputs" {
    module     = module.generate_aws_host_tag_vars
    depends_on = [step.create_tag2]

    variables {
      tag_name  = step.create_tag2.string
      tag_value = "test"
    }
  }

  step "create_isolated_target" {
    module = module.aws_target
    depends_on = [
      step.create_base_infra,
      step.create_isolated_worker
    ]

    variables {
      ami_id               = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      aws_ssh_keypair_name = var.aws_ssh_keypair_name
      enos_user            = var.enos_user
      instance_type        = var.target_instance_type
      vpc_id               = step.create_base_infra.vpc_id
      target_count         = 1
      subnet_ids           = step.create_isolated_worker.subnet_ids
      ingress_cidr         = matrix.ip_version == "4" ? ["10.13.9.0/24"] : []
      ingress_ipv6_cidr    = step.create_isolated_worker.worker_ipv6_cidr
      additional_tags      = step.create_tag2_inputs.tag_map
      ip_version           = matrix.ip_version
    }
  }

  step "run_e2e_test" {
    module = module.test_e2e
    depends_on = [
      step.create_boundary_cluster,
      step.create_targets_with_tag1,
      step.iam_setup,
      step.create_isolated_worker,
      step.create_isolated_target
    ]

    variables {
      test_package             = "github.com/hashicorp/boundary/testing/internal/e2e/tests/aws"
      debug_no_run             = var.e2e_debug_no_run
      alb_boundary_api_addr    = step.create_boundary_cluster.alb_boundary_api_addr
      auth_method_id           = step.create_boundary_cluster.auth_method_id
      auth_login_name          = step.create_boundary_cluster.auth_login_name
      auth_password            = step.create_boundary_cluster.auth_password
      local_boundary_dir       = local.local_boundary_dir
      aws_ssh_private_key_path = local.aws_ssh_private_key_path
      target_user              = "ubuntu"
      target_port              = "22"
      aws_access_key_id        = step.iam_setup.access_key_id
      aws_secret_access_key    = step.iam_setup.secret_access_key
      aws_host_set_filter1     = step.create_tag1_inputs.tag_string
      aws_host_set_ips1        = step.create_targets_with_tag1.target_private_ips
      aws_host_set_filter2     = step.create_tag2_inputs.tag_string
      aws_host_set_ips2        = step.create_isolated_target.target_private_ips
      target_address           = step.create_isolated_target.target_private_ips[0]
      worker_tag_isolated      = local.isolated_tag
      max_page_size            = step.create_boundary_cluster.max_page_size
      aws_region               = var.aws_region
      ip_version               = matrix.ip_version
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
    value = step.create_targets_with_tag1.target_public_ips
  }
}
