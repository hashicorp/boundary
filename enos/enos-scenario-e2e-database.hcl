# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

scenario "e2e_database" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  locals {
    aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
    local_boundary_dir       = abspath(var.local_boundary_dir)
    tags = merge({
      "Project Name" : var.project_name
      "Project" : "Enos",
      "Environment" : "ci"
    }, var.tags)
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

  step "create_tag" {
    module = module.random_stringifier
  }

  step "get_subnets" {
    module = module.map2list
    variables {
      map = step.create_base_infra.vpc_subnets
    }
  }

  step "create_tag_inputs" {
    module     = module.generate_aws_host_tag_vars
    depends_on = [step.create_tag]

    variables {
      tag_name  = step.create_tag.string
      tag_value = "true"
    }
  }

  step "create_targets_with_tag" {
    module     = module.target
    depends_on = [step.create_base_infra]

    variables {
      ami_id               = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      aws_ssh_keypair_name = var.aws_ssh_keypair_name
      enos_user            = var.enos_user
      instance_type        = var.target_instance_type
      vpc_id               = step.create_base_infra.vpc_id
      target_count         = 1
      additional_tags      = step.create_tag_inputs.tag_map
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
    module = module.test_e2e
    depends_on = [
      step.create_targets_with_tag,
      step.iam_setup,
    ]

    variables {
      test_package             = "github.com/hashicorp/boundary/testing/internal/e2e/tests/database"
      debug_no_run             = var.e2e_debug_no_run
      local_boundary_dir       = local.local_boundary_dir
      target_user              = "ubuntu"
      aws_ssh_private_key_path = local.aws_ssh_private_key_path
      aws_access_key_id        = step.iam_setup.access_key_id
      aws_secret_access_key    = step.iam_setup.secret_access_key
      aws_host_set_filter1     = step.create_tag_inputs.tag_string
    }
  }

  output "test_results" {
    value = step.run_e2e_test.test_results
  }
}
