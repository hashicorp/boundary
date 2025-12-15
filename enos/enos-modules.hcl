# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

module "aws_az_finder" {
  source = "./modules/aws_az_finder"
}

module "bats_deps" {
  source = "./modules/bats_deps"
}

module "aws_boundary" {
  source = "./modules/aws_boundary"

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

module "aws_worker" {
  source = "./modules/aws_worker"

  common_tags = {
    "Project" : "Enos",
    "Project Name" : "qti-enos-boundary",
    "Enos User" : var.enos_user,
    "Environment" : var.environment
  }

  ssh_aws_keypair = var.aws_ssh_keypair_name
}

module "aws_bucket" {
  source = "./modules/aws_bucket"
}

module "aws_rdp_domain_controller" {
  source = "./modules/aws_rdp_domain_controller"
}

module "aws_rdp_member_server" {
  source = "./modules/aws_rdp_member_server"
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

module "aws_iam_setup" {
  source = "./modules/aws_iam_setup"
}

module "aws_vpc" {
  source = "./modules/aws_vpc"

  environment = var.environment
  common_tags = {
    "Project" : "Enos",
    "Project Name" : "qti-enos-boundary",
    "Enos User" : var.enos_user,
    "Environment" : var.environment
  }
}

module "aws_vpc_ipv6" {
  source = "./modules/aws_vpc_ipv6"

  environment = var.environment
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

module "aws_target" {
  source       = "./modules/aws_target"
  target_count = var.target_count

  project_name = "qti-enos-boundary"
  environment  = var.environment
  enos_user    = var.enos_user
}

module "aws_windows_client" {
  source = "./modules/aws_windows_client"
}

module "aws_rdp_member_server_with_worker" {
  source = "./modules/aws_rdp_member_server_with_worker"
}

module "vault" {
  source = "./modules/aws_vault"

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

module "test_e2e_docker" {
  source = "./modules/test_e2e_docker"
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

module "docker_boundary_cmd" {
  source = "./modules/docker_boundary_cmd"
}

module "docker_openssh_server" {
  source = "./modules/docker_openssh_server"
}

module "docker_openssh_server_ca_key" {
  source = "./modules/docker_openssh_server_ca_key"
}

module "docker_worker" {
  source = "./modules/docker_worker"
}

module "docker_network" {
  source = "./modules/docker_network"
}

module "docker_check_health" {
  source = "./modules/docker_check_health"
}

module "docker_ldap" {
  source = "./modules/docker_ldap"
}

module "docker_minio" {
  source = "./modules/docker_minio"
}

module "gcp_iam_setup" {
  source         = "./modules/gcp_iam_setup"
  gcp_project_id = var.gcp_project_id
}

module "gcp_target" {
  source       = "./modules/gcp_target"
  target_count = var.target_count
  environment  = var.environment
  enos_user    = var.enos_user
}
