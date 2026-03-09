# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# This scenario creates a single Windows ec2 instance that acts as a domain
# controller. This can be used as an RDP target for boundary.
scenario "e2e_aws_rdp_target" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  matrix {
    rdp_server = ["2016", "2019", "2022", "2025"]
  }

  locals {
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
        var.windows_instance_type,
      ]
    }
  }

  step "create_base_infra" {
    module = module.aws_vpc_ipv6

    depends_on = [
      step.find_azs,
    ]

    variables {
      availability_zones = step.find_azs.availability_zones
      common_tags        = local.tags
    }
  }

  step "create_rdp_domain_controller" {
    module = module.aws_rdp_domain_controller
    depends_on = [
      step.create_base_infra,
    ]

    variables {
      vpc_id                   = step.create_base_infra.vpc_id
      server_version           = matrix.rdp_server
      rdp_target_instance_type = var.windows_instance_type
    }
  }

  output "rdp_target_admin_username" {
    value = step.create_rdp_domain_controller.admin_username
  }

  output "rdp_target_admin_password" {
    value = step.create_rdp_domain_controller.password
  }

  output "rdp_target_public_dns_address" {
    value = step.create_rdp_domain_controller.public_dns_address
  }

  output "rdp_target_public_ip" {
    value = step.create_rdp_domain_controller.public_ip
  }

  output "rdp_target_private_ip" {
    value = step.create_rdp_domain_controller.private_ip
  }

  output "rdp_target_ipv6" {
    value = step.create_rdp_domain_controller.ipv6
  }
}
