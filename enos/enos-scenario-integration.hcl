scenario "integration" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  matrix {
    builder = ["local", "crt"]
    test    = ["cli_ui"]
  }

  locals {
    aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
    boundary_install_dir     = abspath(var.boundary_install_dir)
    local_boundary_dir       = abspath(var.local_boundary_dir)
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

  step "ensure_bats_and_deps_are_installed" {
    skip_step = matrix.test != "cli_ui"
    module    = module.bats_deps
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

  step "create_db_password" {
    module = module.random_stringifier
  }

  step "build_boundary" {
    module = matrix.builder == "crt" ? module.build_crt : module.build_local

    variables {
      path = local.build_path[matrix.builder]
    }
  }

  step "create_base_infra" {
    module = module.infra

    variables {
      availability_zones = step.find_azs.availability_zones
      common_tags        = local.tags
    }
  }

  step "create_boundary_cluster" {
    module = module.boundary
    depends_on = [
      step.create_base_infra,
      step.build_boundary
    ]

    variables {
      boundary_install_dir     = local.boundary_install_dir
      common_tags              = local.tags
      controller_instance_type = var.controller_instance_type
      controller_count         = var.controller_count
      db_pass                  = step.create_db_password.string
      kms_key_arn              = step.create_base_infra.kms_key_arn
      local_artifact_path      = step.build_boundary.artifact_path
      ubuntu_ami_id            = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      vpc_id                   = step.create_base_infra.vpc_id
      worker_count             = var.worker_count
      worker_instance_type     = var.worker_instance_type
    }
  }

  step "run_test_cli_ui" {
    skip_step  = matrix.test != "cli_ui"
    module     = module.test_cli_ui
    depends_on = [step.create_boundary_cluster]

    variables {
      alb_boundary_api_addr = step.create_boundary_cluster.alb_boundary_api_addr
      auth_login_name       = step.create_boundary_cluster.auth_login_name
      auth_method_id        = step.create_boundary_cluster.auth_method_id
      auth_password         = step.create_boundary_cluster.auth_password
      auth_user_id          = step.create_boundary_cluster.auth_user_id
      boundary_install_dir  = local.boundary_install_dir
      controller_ips        = step.create_boundary_cluster.controller_ips
      host_catalog_id       = step.create_boundary_cluster.host_catalog_id
      host_id               = step.create_boundary_cluster.host_id
      host_set_id           = step.create_boundary_cluster.host_set_id
      local_boundary_dir    = local.local_boundary_dir
      project_scope_id      = step.create_boundary_cluster.project_scope_id
      org_scope_id          = step.create_boundary_cluster.org_scope_id
      skip_failing_tests    = var.skip_failing_bats_tests
      target_id             = step.create_boundary_cluster.target_id
    }
  }
}
