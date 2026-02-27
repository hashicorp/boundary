# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }

  cloud {
    hostname     = "app.terraform.io"
    organization = "hashicorp-qti"

    workspaces {
      name = "boundary-hcp-resources"
    }
  }
}

data "aws_caller_identity" "current" {}

provider "aws" {
  region = var.aws_region
}

module "generate_ssh_key" {
  source = "../../modules/aws_ssh_keypair"

  enos_user = var.enos_user
}

provider "enos" {
  transport = {
    ssh = {
      user             = "ubuntu"
      private_key_path = module.generate_ssh_key.private_key_path
    }
  }
}

locals {
  worker_instance_type = "t3a.small"
  target_instance_type = "t2.micro"

  egress_tag = "egress"

  license_path      = abspath(var.boundary_license_path)
  boundary_zip_path = abspath(var.boundary_zip_path)

  cluster_tag     = "boundary_hcp_testing"
  project_tag     = "boundary_hcp_testing"
  environment_tag = "hcp"
  tags = merge({
    "Project Name" : local.project_tag,
    "Project" : local.project_tag,
    "Environment" : local.environment_tag,
  })
}

module "find_azs" {
  source = "../../modules/aws_az_finder"

  instance_type = [
    local.worker_instance_type,
    local.target_instance_type
  ]
}

module "license" {
  source = "../../modules/read_license"

  license_path = abspath(local.license_path)
}

module "iam_user" {
  source = "../../modules/aws_iam_setup"

  test_id    = local.environment_tag
  test_email = split(":", data.aws_caller_identity.current.user_id)[1]
}

module "base_infra" {
  source = "../../modules/aws_vpc"

  availability_zones = module.find_azs.availability_zones
  common_tags        = local.tags
}

module "worker" {
  depends_on = [module.base_infra, module.generate_ssh_key]
  source     = "../../modules/aws_boundary"

  controller_count        = 0
  worker_count            = var.worker_count
  db_create               = false
  aws_region              = var.aws_region
  hcp_boundary_cluster_id = var.hcp_boundary_cluster_id
  aws_ssh_keypair_name    = module.generate_ssh_key.key_pair_name
  aws_ssh_private_key     = module.generate_ssh_key.private_key_pem
  boundary_license        = module.license.license
  kms_key_arn             = module.base_infra.kms_key_arn
  ubuntu_ami_id           = module.base_infra.ami_ids["ubuntu"]["amd64"]
  vpc_id                  = module.base_infra.vpc_id
  vpc_tag_module          = module.base_infra.vpc_tag_module
  worker_instance_type    = local.worker_instance_type
  worker_type_tags        = [local.egress_tag]
  worker_config_file_path = "templates/worker_hcp_bsr.hcl"
  recording_storage_path  = "/recordings"
  local_artifact_path     = local.boundary_zip_path
  environment             = local.environment_tag
  project_name            = local.project_tag
  common_tags             = local.tags
}

module "storage_bucket" {
  depends_on = [module.iam_user]
  source     = "../../modules/aws_bucket"

  cluster_tag = local.cluster_tag
  user        = module.iam_user.user_name
  is_user     = true
}

module "target_tags" {
  source = "../../modules/generate_aws_host_tag_vars"

  tag_name  = local.project_tag
  tag_value = "true"
}

module "target" {
  source = "../../modules/aws_target"

  target_count         = var.target_count
  aws_ssh_keypair_name = module.generate_ssh_key.key_pair_name
  aws_ssh_private_key  = module.generate_ssh_key.private_key_pem
  instance_type        = local.target_instance_type
  enos_user            = local.cluster_tag
  environment          = local.environment_tag
  project_name         = local.project_tag
  ami_id               = module.base_infra.ami_ids["ubuntu"]["amd64"]
  vpc_id               = module.base_infra.vpc_id
  subnet_ids           = module.worker.subnet_ids
  additional_tags      = module.target_tags.tag_map
}
