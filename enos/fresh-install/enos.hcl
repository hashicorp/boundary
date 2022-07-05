terraform_cli "default" {
  plugin_cache_dir = abspath("../terraform-plugin-cache")

  provider_installation {
    network_mirror {
      url     = "https://enos-provider-current.s3.amazonaws.com/"
      include = ["hashicorp.com/qti/enos"]
    }
    direct {
      exclude = [
        "hashicorp.com/qti/enos"
      ]
    }
  }

  credentials "app.terraform.io" {
    token = var.tfc_api_token
  }
}

terraform "default" {
  required_version = ">= 1.0.0"

  required_providers {
    enos = {
      version = ">= 0.1.28"
      source  = "hashicorp.com/qti/enos"
    }

    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" "default" {
  region = "us-east-1"
}

provider "enos" "default" {
  transport = {
    ssh = {
      user             = "ubuntu"
      private_key_path = var.aws_ssh_private_key_path
    }
  }
}

module "build" {
  source = "../modules/build"
  path   = "/tmp"
}

module "az_finder" {
  source = "../modules/az_finder"
}

module "random_stringifier" {
  source = "../modules/random_stringifier"
}

module "target" {
  source       = "../modules/target"
  target_count = var.target_count

  project_name = "qti-enos-boundary"
  environment  = var.environment
  enos_user    = var.enos_user
}

module "tests" {
  source = "../modules/tests"
}

module "infra" {
  #source = "../../../../terraform-enos-aws-infra"
  source  = "app.terraform.io/hashicorp-qti/aws-infra/enos"
  version = ">= 0.2.0"

  project_name = "qti-enos-boundary"
  environment  = var.environment
  common_tags = {
    "Project Name" : "qti-enos-boundary",
    "Enos User" : var.enos_user,
    "Environment" : var.environment
  }
}

module "boundary" {
  #source = "../../../terraform-enos-aws-boundary"
  source  = "app.terraform.io/hashicorp-qti/aws-boundary/enos"
  version = ">= 0.2.4"

  project_name = "qti-enos-boundary"
  environment  = var.environment
  common_tags = {
    "Project Name" : "qti-enos-boundary",
    "Enos User" : var.enos_user,
    "Environment" : var.environment
  }

  ssh_aws_keypair = var.aws_ssh_key_pair_name
}

scenario "fresh_install" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  step "find_azs" {
    module = module.az_finder

    variables {
      instance_type = [
        var.worker_instance_type,
        var.controller_instance_type
      ]
    }
  }

  step "random" {
    module = module.random_stringifier
  }

  step "build_boundary" {
    module = module.build
  }

  step "create_base_infra" {
    module = module.infra

    variables {
      availability_zones = step.find_azs.availability_zones
    }
  }

  step "create_boundary_cluster" {
    module = module.boundary
    depends_on = [
      step.create_base_infra,
      step.build_boundary
    ]

    variables {
      ubuntu_ami_id            = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      controller_instance_type = var.controller_instance_type
      worker_instance_type     = var.worker_instance_type
      vpc_id                   = step.create_base_infra.vpc_id
      kms_key_arn              = step.create_base_infra.kms_key_arn
      db_pass                  = step.random.string
      boundary_install_dir     = var.boundary_install_dir
      controller_count         = var.controller_count
      worker_count             = var.worker_count
      local_artifact_path      = step.build_boundary.artifact_path
    }
  }

  step "test_target" {
    module     = module.target
    depends_on = [step.create_base_infra]

    variables {
      ami_id                = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      vpc_id                = step.create_base_infra.vpc_id
      instance_type         = var.target_instance_type
      enos_user             = var.enos_user
      aws_ssh_key_pair_name = var.aws_ssh_key_pair_name
    }
  }

  step "run_tests" {
    module     = module.tests
    depends_on = [step.create_boundary_cluster]

    variables {
      aws_ssh_private_key_path = var.aws_ssh_private_key_path
      target_count             = var.target_count
      boundary_install_dir     = var.boundary_install_dir
      local_boundary_dir       = var.local_boundary_dir
      alb_hostname             = step.create_boundary_cluster.alb_hostname
      controller_ips           = step.create_boundary_cluster.controller_ips
      auth_method_id           = step.create_boundary_cluster.auth_method_id
      auth_login_name          = step.create_boundary_cluster.auth_login_name
      auth_password            = step.create_boundary_cluster.auth_password
      project_scope_id         = step.create_boundary_cluster.project_scope_id
      target_id                = step.create_boundary_cluster.target_id
      target_ips               = step.test_target.target_ips
    }
  }
}
