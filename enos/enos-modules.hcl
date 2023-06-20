# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

module "az_finder" {
  source = "./modules/az_finder"
}

module "bats_deps" {
  source = "./modules/bats_deps"
}

module "boundary" {
  source  = "app.terraform.io/hashicorp-qti/aws-boundary/enos"
  version = ">= 0.6.2"

  project_name = "qti-enos-boundary"
  environment  = var.environment
  common_tags = {
    "Project" : "Enos",
    "Project Name" : "qti-enos-boundary",
    "Enos User" : var.enos_user,
    "Environment" : var.environment
  }

  alb_listener_api_port = var.alb_listener_api_port
  boundary_binary_name  = var.boundary_binary_name
  ssh_aws_keypair       = var.aws_ssh_keypair_name
}

module "worker" {
  source = "./modules/worker"

  common_tags = {
    "Project" : "Enos",
    "Project Name" : "qti-enos-boundary",
    "Enos User" : var.enos_user,
    "Environment" : var.environment
  }

  ssh_aws_keypair = var.aws_ssh_keypair_name
}

module "bucket" {
  source = "./modules/bucket"
}

module "build_crt" {
  source = "./modules/build_crt"
}

module "build_local" {
  source = "./modules/build_local"

  binary_name  = var.boundary_binary_name
  build_target = var.local_build_target
}

module "build_boundary_docker_crt" {
  source = "./modules/build_boundary_docker_crt"
}

module "build_boundary_docker_local" {
  source = "./modules/build_boundary_docker_local"
}

module "generate_aws_host_tag_vars" {
  source = "./modules/generate_aws_host_tag_vars"
}

module "iam_setup" {
  source = "./modules/iam_setup"
}

module "infra" {
  source  = "app.terraform.io/hashicorp-qti/aws-infra/enos"
  version = ">= 0.3.1"

  project_name = "qti-enos-boundary"
  environment  = var.environment
  common_tags = {
    "Project" : "Enos",
    "Project Name" : "qti-enos-boundary",
    "Enos User" : var.enos_user,
    "Environment" : var.environment
  }
}

module "read_license" {
  source = "./modules/read_license"
}

module "random_stringifier" {
  source = "./modules/random_stringifier"
}

module "map2list" {
  source = "./modules/map2list"
}

module "target" {
  source       = "./modules/target"
  target_count = var.target_count

  project_name = "qti-enos-boundary"
  environment  = var.environment
  enos_user    = var.enos_user
}

module "vault" {
  source = "app.terraform.io/hashicorp-qti/aws-vault/enos"

  project_name = "qti-enos-boundary"
  environment  = var.environment
  common_tags = {
    "Project" : "Enos",
    "Project Name" : "qti-enos-boundary",
    "Enos User" : var.enos_user,
    "Environment" : var.environment
  }

  ssh_aws_keypair = var.aws_ssh_keypair_name
}

module "test_e2e" {
  source       = "./modules/test_e2e"
  test_timeout = var.go_test_timeout
}

module "test_e2e_ui" {
  source = "./modules/test_e2e_ui"
}

module "test_smoke" {
  source = "./modules/test_smoke"
}

module "docker_postgres" {
  source = "./modules/docker_postgres"
}

module "docker_vault" {
  source = "./modules/docker_vault"
}

module "docker_boundary" {
  source = "./modules/docker_boundary"
}

module "docker_openssh_server" {
  source = "./modules/docker_openssh_server"
}

module "docker_network" {
  source = "./modules/docker_network"
}
