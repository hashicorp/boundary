# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# For this scenario to work, add the following line to /etc/hosts
# 127.0.0.1 localhost boundary

scenario "e2e_docker_base_with_gcp" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.enos.default,
    provider.google.default
  ]

  matrix {
    builder = ["local", "crt"]
  }

  locals {
    local_boundary_src_dir     = var.local_boundary_src_dir != null ? abspath(var.local_boundary_src_dir) : null
    boundary_docker_image_file = abspath(var.boundary_docker_image_file)
    license_path               = abspath(var.boundary_license_path != null ? var.boundary_license_path : joinpath(path.root, "./support/boundary.hclic"))
    gcp_private_key            = var.gcp_private_key_path != null ? file(var.gcp_private_key_path) : var.gcp_private_key

    network_cluster = "e2e_gcp"

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

  step "create_docker_network" {
    module = module.docker_network
    variables {
      network_name = local.network_cluster
    }
  }

  step "create_boundary_database" {
    depends_on = [
      step.create_docker_network
    ]
    variables {
      image_name   = "${var.docker_mirror}/library/postgres:latest"
      network_name = [local.network_cluster]
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
      step.create_docker_network,
      step.create_boundary_database,
      step.build_boundary_docker_image
    ]
    variables {
      image_name       = step.build_boundary_docker_image.image_name
      network_name     = [local.network_cluster]
      database_network = local.network_cluster
      postgres_address = step.create_boundary_database.address
      boundary_license = var.boundary_edition != "oss" ? step.read_license.license : ""
    }
  }

  step "create_test_id" {
    module = module.random_stringifier
    variables {
      length = 5
    }
  }

  step "create_gcp_target" {
    module = module.gcp_target

    variables {
      enos_user     = var.enos_user
      instance_type = var.gcp_target_instance_type
      gcp_zone      = var.gcp_zone
      target_count  = 1
    }
  }

  step "run_e2e_test" {
    module = module.test_e2e_docker
    depends_on = [
      step.create_boundary,
      step.create_gcp_target
    ]
    variables {
      test_package           = "github.com/hashicorp/boundary/testing/internal/e2e/tests/gcp"
      docker_mirror          = var.docker_mirror
      network_name           = step.create_docker_network.network_name
      go_version             = var.go_version
      debug_no_run           = var.e2e_debug_no_run
      alb_boundary_api_addr  = step.create_boundary.address
      auth_method_id         = step.create_boundary.auth_method_id
      auth_login_name        = step.create_boundary.login_name
      auth_password          = step.create_boundary.password
      local_boundary_dir     = step.build_boundary_docker_image.cli_zip_path
      local_boundary_src_dir = local.local_boundary_src_dir
      gcp_host_set_filter1   = step.create_gcp_target.filter_label1
      gcp_host_set_filter2   = step.create_gcp_target.filter_label2
      gcp_private_key_id     = var.gcp_private_key_id
      gcp_private_key        = local.gcp_private_key
      gcp_zone               = var.gcp_zone
      gcp_project_id         = var.gcp_project_id
      gcp_client_email       = var.gcp_client_email
      gcp_target_ssh_key     = step.create_gcp_target.target_ssh_key
      gcp_host_set_ips       = step.create_gcp_target.target_ips
      target_address         = step.create_gcp_target.target_public_ips[0]
      target_port            = "22"
      target_user            = "ubuntu"
      max_page_size          = step.create_boundary.max_page_size
    }
  }
}
