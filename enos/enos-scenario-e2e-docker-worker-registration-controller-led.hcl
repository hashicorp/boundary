# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

scenario "e2e_docker_worker_registration_controller_led" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default

  matrix {
    builder = ["local", "crt"]
  }

  locals {
    aws_ssh_private_key_path   = var.aws_ssh_private_key_path != null ? abspath(var.aws_ssh_private_key_path) : null
    local_boundary_dir         = var.local_boundary_dir != null ? abspath(var.local_boundary_dir) : null
    boundary_docker_image_file = abspath(var.boundary_docker_image_file)
    license_path               = abspath(var.boundary_license_path != null ? var.boundary_license_path : joinpath(path.root, "./support/boundary.hclic"))

    network_cluster  = "e2e_cluster"
    network_host     = "e2e_host"
    network_database = "e2e_db"

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

  step "get_boundary_binary" {
    skip_step = local.local_boundary_dir != null ? true : false
    module    = module.get_binary_path

    variables {
      name = "boundary"
    }
  }

  step "get_boundary_edition" {
    module = module.get_boundary_edition
  }


  step "build_boundary_docker_image" {
    module = matrix.builder == "crt" ? module.build_boundary_docker_crt : module.build_boundary_docker_local

    variables {
      path           = matrix.builder == "crt" ? local.boundary_docker_image_file : ""
      cli_build_path = local.build_path[matrix.builder]
      edition        = step.get_boundary_edition.edition
    }
  }

  step "generate_ssh_key" {
    module = module.ssh_keypair

    variables {
      local_key_path = local.aws_ssh_private_key_path
    }
  }

  step "create_docker_network_database" {
    module = module.docker_network
    variables {
      network_name = local.network_database
    }
  }

  step "create_docker_network_cluster" {
    module = module.docker_network
    variables {
      network_name = local.network_cluster
    }
  }

  step "create_docker_network_host" {
    module = module.docker_network
    variables {
      network_name = local.network_host
    }
  }

  step "create_boundary_database" {
    depends_on = [
      step.create_docker_network_cluster
    ]
    variables {
      image_name   = "${var.docker_mirror}/library/postgres:latest"
      network_name = [local.network_database]
    }
    module = module.docker_postgres
  }

  step "read_license" {
    module = module.read_license

    variables {
      license_path = local.license_path
      license      = var.boundary_license
      edition      = step.get_boundary_edition.edition
    }
  }

  step "create_boundary" {
    module = module.docker_boundary
    depends_on = [
      step.create_docker_network_cluster,
      step.create_docker_network_database,
      step.create_boundary_database,
      step.build_boundary_docker_image
    ]
    variables {
      image_name       = step.build_boundary_docker_image.image_name
      network_name     = [local.network_cluster, local.network_database]
      database_network = local.network_database
      postgres_address = step.create_boundary_database.address
      boundary_license = step.read_license.license
      config_file      = "boundary-config.hcl"
    }
  }

  step "get_worker_token" {
    module     = module.docker_boundary_cmd
    depends_on = [step.create_boundary]
    variables {
      address      = step.create_boundary.container_address
      image_name   = step.build_boundary_docker_image.image_name
      network_name = local.network_cluster
      login_name   = step.create_boundary.login_name
      password     = step.create_boundary.password
      script       = "get_worker_token.sh"
    }
  }

  step "create_vault" {
    module = module.docker_vault
    depends_on = [
      step.create_docker_network_cluster
    ]
    variables {
      image_name   = "${var.docker_mirror}/hashicorp/vault:${var.vault_version}"
      network_name = [local.network_cluster]
    }
  }

  step "create_host" {
    module = module.docker_openssh_server
    depends_on = [
      step.create_docker_network_host
    ]
    variables {
      image_name            = "${var.docker_mirror}/linuxserver/openssh-server:latest"
      network_name          = [local.network_host]
      private_key_file_path = step.generate_ssh_key.private_key_path
    }
  }

  locals {
    egress_tag = "egress"
  }

  step "create_worker" {
    module = module.docker_worker
    depends_on = [
      step.create_docker_network_cluster,
      step.create_docker_network_host,
      step.build_boundary_docker_image,
      step.create_boundary
    ]
    variables {
      image_name       = step.build_boundary_docker_image.image_name
      boundary_license = step.read_license.license
      config_file      = "worker-config-controller-led.hcl"
      container_name   = "worker"
      initial_upstream = step.create_boundary.upstream_address
      network_name     = [local.network_cluster, local.network_host]
      tags             = [local.egress_tag]
      port             = "9402"
      token            = step.get_worker_token.output["item"]["controller_generated_activation_token"]
    }
  }

  step "run_e2e_test" {
    module = module.test_e2e_docker
    depends_on = [
      step.create_boundary,
      step.create_vault,
      step.create_host,
      step.create_worker,
    ]
    variables {
      is_ci                    = var.is_ci
      test_package             = "github.com/hashicorp/boundary/testing/internal/e2e/tests/base_with_worker"
      network_name             = step.create_docker_network_cluster.network_name
      alb_boundary_api_addr    = step.create_boundary.address
      auth_method_id           = step.create_boundary.auth_method_id
      auth_login_name          = step.create_boundary.login_name
      auth_password            = step.create_boundary.password
      local_boundary_dir       = local.local_boundary_dir != null ? local.local_boundary_dir : step.get_boundary_binary.path
      aws_ssh_private_key_path = step.generate_ssh_key.private_key_path
      target_address           = step.create_host.address
      target_port              = step.create_host.port
      target_user              = "ubuntu"
      vault_addr_public        = step.create_vault.address_public
      vault_addr_private       = step.create_vault.address_private
      vault_root_token         = step.create_vault.token
      vault_port               = step.create_vault.port
      worker_tag_egress        = local.egress_tag
      worker_tag_collocated    = step.create_boundary.worker_tag
      max_page_size            = step.create_boundary.max_page_size
    }
  }
}
