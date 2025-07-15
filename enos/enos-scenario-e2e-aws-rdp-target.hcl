# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

scenario "e2e_aws_rdp_target" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  matrix {
    rdp_server = ["2016", "2019", "2022", "2025"]
    ip_version = ["4", "dual"]
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
        var.worker_instance_type,
        var.controller_instance_type
      ]
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

  step "create_rdp_server" {
    module = module.aws_rdp_server
    depends_on = [
      step.create_base_infra,
    ]

    variables {
      vpc_id         = step.create_base_infra.vpc_id
      server_version = matrix.rdp_server
    }
  }

  output "rdp_target_admin_username" {
    value = step.create_rdp_server.admin_username
  }

  output "rdp_target_admin_password" {
    value = step.create_rdp_server.password
  }

  output "rdp_target_public_dns_address" {
    value = step.create_rdp_server.public-dns-address
  }

  output "rdp_target_public_ip" {
    value = step.create_rdp_server.public_ip
  }

  output "rdp_target_private_ip" {
    value = step.create_rdp_server.private_ip
  }
}