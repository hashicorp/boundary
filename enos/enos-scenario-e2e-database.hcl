# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

scenario "e2e_database" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
  ]

  locals {
    aws_ssh_private_key_path = var.aws_ssh_private_key_path != null ? abspath(var.aws_ssh_private_key_path) : null
    local_boundary_dir       = var.local_boundary_dir != null ? abspath(var.local_boundary_dir) : null
    license_path             = abspath(var.boundary_license_path != null ? var.boundary_license_path : joinpath(path.root, "./support/boundary.hclic"))

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

  step "read_license" {
    module = module.read_license

    variables {
      license_path = local.license_path
      license      = var.boundary_license
      edition      = step.get_boundary_edition.edition
    }
  }

  step "generate_ssh_key" {
    module = module.aws_ssh_keypair

    variables {
      local_key_path         = local.aws_ssh_private_key_path
      local_aws_keypair_name = var.aws_ssh_keypair_name != null ? var.aws_ssh_keypair_name : null
    }
  }
  step "find_azs" {
    module = module.aws_az_finder

    variables {
      instance_type = [
        var.target_instance_type
      ]
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
    module     = module.aws_target
    depends_on = [step.create_base_infra, step.generate_ssh_key]

    variables {
      ami_id                   = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      aws_ssh_keypair_name     = step.generate_ssh_key.key_pair_name
      aws_ssh_private_key_path = step.generate_ssh_key.private_key_path
      enos_user                = var.enos_user
      instance_type            = var.target_instance_type
      vpc_id                   = step.create_base_infra.vpc_id
      target_count             = 1
      additional_tags          = step.create_tag_inputs.tag_map
      subnet_ids               = step.get_subnets.list
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

  step "run_e2e_test" {
    module = module.test_e2e
    depends_on = [
      step.create_targets_with_tag,
      step.iam_setup,
      step.generate_ssh_key
    ]

    variables {
      is_ci                    = var.is_ci
      test_package             = "github.com/hashicorp/boundary/testing/internal/e2e/tests/database"
      boundary_license         = step.read_license.license
      local_boundary_dir       = local.local_boundary_dir != null ? local.local_boundary_dir : step.get_boundary_binary.path
      target_user              = "ubuntu"
      aws_ssh_private_key_path = step.generate_ssh_key.private_key_path
      aws_access_key_id        = step.iam_setup.access_key_id
      aws_secret_access_key    = step.iam_setup.secret_access_key
      aws_host_set_filter1     = step.create_tag_inputs.tag_string
      max_page_size            = 10
      aws_region               = var.aws_region
      vault_version            = var.vault_version
    }
  }

  output "test_results" {
    value = step.run_e2e_test.test_results
  }
}
