# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# For this scenario to work, add the following line to /etc/hosts
# 127.0.0.1 localhost boundary

scenario "e2e_docker" {
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
    boundary_docker_image_file = abspath(var.boundary_docker_image_file)
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
      path = matrix.builder == "crt" ? local.boundary_docker_image_file : "/tmp/boundary_docker_image.tar"
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

  step "run_e2e_test" {
    module = module.test_e2e
    depends_on = [
      step.create_boundary,
      step.create_vault,
      step.create_host,
      step.create_boundary_database
    ]

    variables {
      test_package             = "github.com/hashicorp/boundary/testing/internal/e2e/tests/static_with_vault"
      debug_no_run             = var.e2e_debug_no_run
      alb_boundary_api_addr    = step.create_boundary.address
      auth_method_id           = step.create_boundary.auth_method_id
      auth_login_name          = step.create_boundary.login_name
      auth_password            = step.create_boundary.password
      local_boundary_dir       = local.local_boundary_dir
      aws_ssh_private_key_path = local.aws_ssh_private_key_path
      target_ip                = step.create_host.address
      target_port              = step.create_host.port
      target_user              = "ubuntu"
      vault_addr               = step.create_vault.address
      vault_addr_internal      = step.create_vault.address_internal
      vault_root_token         = step.create_vault.token
    }
  }

  output "test_results" {
    value = step.run_e2e_test.test_results
  }
}
