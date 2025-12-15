# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# For this scenario to work, add the following line to /etc/hosts
# 127.0.0.1 localhost boundary
# 127.0.0.1 localhost worker

scenario "e2e_docker_worker_registration_worker_led" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.enos.default
  ]

  matrix {
    builder = ["local", "crt"]
  }

  locals {
    aws_ssh_private_key_path   = abspath(var.aws_ssh_private_key_path)
    local_boundary_src_dir     = var.local_boundary_src_dir != null ? abspath(var.local_boundary_src_dir) : null
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

  step "build_boundary_docker_image" {
    module = matrix.builder == "crt" ? module.build_boundary_docker_crt : module.build_boundary_docker_local

    variables {
      path           = matrix.builder == "crt" ? local.boundary_docker_image_file : ""
      cli_build_path = local.build_path[matrix.builder]
      edition        = var.boundary_edition
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
    skip_step = var.boundary_edition == "oss"
    module    = module.read_license

    variables {
      license_path = local.license_path
      license      = var.boundary_license
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
      boundary_license = var.boundary_edition != "oss" ? step.read_license.license : ""
      config_file      = "boundary-config.hcl"
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
      private_key_file_path = local.aws_ssh_private_key_path
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
      image_name              = step.build_boundary_docker_image.image_name
      boundary_license        = var.boundary_edition != "oss" ? step.read_license.license : ""
      config_file             = "worker-config-worker-led.hcl"
      container_name          = "worker"
      initial_upstream        = step.create_boundary.upstream_address
      network_name            = [local.network_cluster, local.network_host]
      tags                    = [local.egress_tag]
      port                    = "9402"
      worker_led_registration = true
    }
  }

  step "init_worker" {
    module = module.docker_boundary_cmd
    depends_on = [
      step.create_docker_network_cluster,
      step.create_boundary,
      step.create_worker,
    ]
    variables {
      address      = step.create_boundary.address
      image_name   = step.build_boundary_docker_image.image_name
      network_name = local.network_cluster
      login_name   = step.create_boundary.login_name
      password     = step.create_boundary.password
      script       = "create_worker.sh"
      worker_token = step.create_worker.worker_led_token
    }
  }

  step "check_worker_health" {
    module     = module.docker_check_health
    depends_on = [step.init_worker]

    variables {
      container_name = "worker"
    }
  }

  step "run_e2e_test" {
    module = module.test_e2e_docker
    depends_on = [
      step.create_boundary,
      step.create_vault,
      step.create_host,
      step.create_worker,
      step.check_worker_health,
    ]
    variables {
      test_package             = "github.com/hashicorp/boundary/testing/internal/e2e/tests/base_with_worker"
      docker_mirror            = var.docker_mirror
      network_name             = step.create_docker_network_cluster.network_name
      go_version               = var.go_version
      debug_no_run             = var.e2e_debug_no_run
      alb_boundary_api_addr    = step.create_boundary.address
      auth_method_id           = step.create_boundary.auth_method_id
      auth_login_name          = step.create_boundary.login_name
      auth_password            = step.create_boundary.password
      local_boundary_dir       = step.build_boundary_docker_image.cli_zip_path
      local_boundary_src_dir   = local.local_boundary_src_dir
      aws_ssh_private_key_path = local.aws_ssh_private_key_path
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
