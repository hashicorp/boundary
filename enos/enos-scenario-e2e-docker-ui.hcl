# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# For this scenario to work, add the following line to /etc/hosts
# 127.0.0.1 localhost boundary

scenario "e2e_docker_ui" {
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
    aws_ssh_private_key_path   = abspath(var.aws_ssh_private_key_path)
    local_boundary_dir         = abspath(var.local_boundary_dir)
    local_boundary_ui_src_dir  = abspath(var.local_boundary_ui_src_dir)
    boundary_docker_image_file = abspath(var.boundary_docker_image_file)
    license_path               = abspath(var.boundary_license_path != null ? var.boundary_license_path : joinpath(path.root, "./support/boundary.hclic"))

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

  step "build_boundary_docker_image" {
    module = matrix.builder == "crt" ? module.build_boundary_docker_crt : module.build_boundary_docker_local

    variables {
      path           = matrix.builder == "crt" ? local.boundary_docker_image_file : "/tmp/boundary_docker_image.tar"
      cli_build_path = local.build_path[matrix.builder]
    }
  }

  step "create_docker_network" {
    module = module.docker_network
  }

  step "create_boundary_database" {
    depends_on = [
      step.create_docker_network
    ]
    variables {
      image_name   = "${var.docker_mirror}/library/postgres:latest"
      network_name = step.create_docker_network.network_name
    }
    module = module.docker_postgres
  }

  step "read_license" {
    skip_step = var.boundary_edition == "oss"
    module    = module.read_license

    variables {
      file_name = local.license_path
    }
  }

  step "create_boundary" {
    module = module.docker_boundary
    depends_on = [
      step.create_docker_network,
      step.create_boundary_database,
      step.build_boundary_docker_image
    ]
    variables {
      image_name       = matrix.builder == "crt" ? var.boundary_docker_image_name : step.build_boundary_docker_image.image_name
      network_name     = step.create_docker_network.network_name
      postgres_address = step.create_boundary_database.address
      boundary_license = var.boundary_edition != "oss" ? step.read_license.license : ""
    }
  }

  step "create_vault" {
    module = module.docker_vault
    depends_on = [
      step.create_docker_network
    ]
    variables {
      image_name   = "${var.docker_mirror}/hashicorp/vault:${var.vault_version}"
      network_name = step.create_docker_network.network_name
    }
  }

  step "create_host" {
    module = module.docker_openssh_server
    depends_on = [
      step.create_docker_network
    ]
    variables {
      image_name            = "${var.docker_mirror}/linuxserver/openssh-server:latest"
      network_name          = step.create_docker_network.network_name
      private_key_file_path = local.aws_ssh_private_key_path
    }
  }

  step "find_azs" {
    module = module.az_finder

    variables {
      instance_type = [
        var.worker_instance_type,
        var.controller_instance_type
      ]
    }
  }

  step "create_base_infra" {
    module = module.infra
    depends_on = [
      step.find_azs,
    ]

    variables {
      availability_zones = step.find_azs.availability_zones
      common_tags        = local.tags
    }
  }

  step "get_subnets" {
    module = module.map2list
    variables {
      map = step.create_base_infra.vpc_subnets
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
    module     = module.target
    depends_on = [step.create_base_infra]

    variables {
      ami_id               = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      aws_ssh_keypair_name = var.aws_ssh_keypair_name
      enos_user            = var.enos_user
      instance_type        = var.target_instance_type
      vpc_id               = step.create_base_infra.vpc_id
      target_count         = 2
      additional_tags      = step.create_tag1_inputs.tag_map
      subnet_ids           = step.get_subnets.list
    }
  }

  step "create_test_id" {
    module = module.random_stringifier
    variables {
      length = 5
    }
  }

  step "iam_setup" {
    module = module.iam_setup
    depends_on = [
      step.create_base_infra,
      step.create_test_id
    ]

    variables {
      test_id    = step.create_test_id.string
      test_email = var.test_email
    }
  }

  step "run_e2e_test" {
    module = module.test_e2e_ui
    depends_on = [
      step.create_boundary,
      step.create_vault,
      step.create_host,
      step.create_boundary_database,
      step.create_targets_with_tag1,
      step.iam_setup,
    ]

    variables {
      debug_no_run              = var.e2e_debug_no_run
      alb_boundary_api_addr     = step.create_boundary.address_localhost
      auth_method_id            = step.create_boundary.auth_method_id
      auth_login_name           = step.create_boundary.login_name
      auth_password             = step.create_boundary.password
      local_boundary_dir        = local.local_boundary_dir
      local_boundary_ui_src_dir = local.local_boundary_ui_src_dir
      aws_ssh_private_key_path  = local.aws_ssh_private_key_path
      target_ip                 = step.create_host.address
      target_port               = step.create_host.port
      target_user               = "ubuntu"
      vault_addr                = step.create_vault.address
      vault_addr_internal       = step.create_vault.address_internal
      vault_root_token          = step.create_vault.token
      vault_port                = step.create_vault.port
      aws_access_key_id         = step.iam_setup.access_key_id
      aws_secret_access_key     = step.iam_setup.secret_access_key
      aws_host_set_filter1      = step.create_tag1_inputs.tag_string
      aws_host_set_ips1         = step.create_targets_with_tag1.target_ips
    }
  }

  output "test_results" {
    value = step.run_e2e_test.test_results
  }
}
