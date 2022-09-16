module "az_finder" {
  source = "./modules/az_finder"
}

module "binary_finder" {
  source = "./modules/binary_finder"
}

module "boundary" {
  source  = "app.terraform.io/hashicorp-qti/aws-boundary/enos"
  version = ">= 0.2.6"

  project_name = "qti-enos-boundary"
  environment  = var.environment
  common_tags = {
    "Project" : "Enos",
    "Project Name" : "qti-enos-boundary",
    "Enos User" : var.enos_user,
    "Environment" : var.environment
  }

  ssh_aws_keypair       = var.aws_ssh_keypair_name
  alb_listener_api_port = var.alb_listener_api_port
}

module "bats_deps" {
  source = "./modules/bats_deps"
}

module "build_crt" {
  source = "./modules/build_crt"
}

module "build_local" {
  source = "./modules/build_local"
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

module "random_stringifier" {
  source = "./modules/random_stringifier"
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

module "test_smoke" {
  source = "./modules/test_smoke"
}

module "test_cli_ui" {
  source = "./modules/test_cli_ui"
}

module "test_e2e" {
  source = "./modules/test_e2e"
}
