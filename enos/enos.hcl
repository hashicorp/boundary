terraform_cli "default" {
  plugin_cache_dir = abspath("./terraform-plugin-cache")

  provider_installation {
    network_mirror {
      url     = "https://enos-provider-stable.s3.amazonaws.com/"
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
      source  = "hashicorp.com/qti/enos"
      version = ">= 0.2.1"
    }

    aws = {
      source = "hashicorp/aws"
    }

    random = {
      source  = "hashicorp/random"
      version = "3.3.2"
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
      private_key_path = abspath(var.aws_ssh_private_key_path)
    }
  }
}

provider "random" "default" {}

module "az_finder" {
  source = "./modules/az_finder"
}

module "nomad_cluster" {
  source = "./modules/aws_nomad"

  project_name = var.project_name
  environment  = var.environment
  common_tags = {
    "Project Name" : var.project_name,
    "Environment" : var.environment
  }
  ssh_aws_keypair   = var.aws_ssh_keypair_name
  nomad_cluster_tag = "nomad"
  nomad_release = {
    version = var.nomad_version
    edition = "oss"
  }
}

module "boundary" {
  #source = "../../terraform-enos-aws-boundary"
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
  # source = "../../../terraform-enos-aws-infra"
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

module "test_smoke" {
  source = "./modules/test_smoke"
}

module "test_cli_ui" {
  source = "./modules/test_cli_ui"
}

module "nomad_job" {
  source = "./modules/nomad_job"
}

module "alb_boundary" {
  source = "./modules/alb_boundary"
}

scenario "integration" {
  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.default
  ]

  matrix {
    builder = ["local", "crt"]
    test    = ["smoke", "cli_ui"]
  }

  locals {
    aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
    boundary_install_dir     = abspath(var.boundary_install_dir)
    local_boundary_dir       = abspath(var.local_boundary_dir)
    build_path = {
      "local" = "/tmp",
      "crt"   = var.crt_bundle_path == null ? null : abspath(var.crt_bundle_path)
    }
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

  step "launch_smoke_targets" {
    skip_step  = matrix.test != "smoke"
    module     = module.target
    depends_on = [step.create_base_infra]

    variables {
      ami_id               = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      aws_ssh_keypair_name = var.aws_ssh_keypair_name
      enos_user            = var.enos_user
      instance_type        = var.target_instance_type
      vpc_id               = step.create_base_infra.vpc_id
    }
  }

  step "run_test_smoke" {
    skip_step  = matrix.test != "smoke"
    module     = module.test_smoke
    depends_on = [step.create_boundary_cluster]

    variables {
      alb_boundary_api_addr    = step.create_boundary_cluster.alb_boundary_api_addr
      auth_login_name          = step.create_boundary_cluster.auth_login_name
      auth_method_id           = step.create_boundary_cluster.auth_method_id
      auth_password            = step.create_boundary_cluster.auth_password
      aws_ssh_private_key_path = local.aws_ssh_private_key_path
      boundary_install_dir     = local.boundary_install_dir
      controller_ips           = step.create_boundary_cluster.controller_ips
      local_boundary_dir       = local.local_boundary_dir
      project_scope_id         = step.create_boundary_cluster.project_scope_id
      target_count             = var.target_count
      target_id                = step.create_boundary_cluster.target_id
      target_ips               = step.launch_smoke_targets.target_ips
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

scenario "make_nomad_cluster" {
  providers = [
    provider.enos.default,
    provider.aws.default,
    provider.random.default,
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

  step "create_base_infra" {
    module = module.infra

    variables {
      availability_zones = step.find_azs.availability_zones
    }
  }

  step "provision_nomad_cluster" {
    module     = module.nomad_cluster
    depends_on = [step.create_base_infra]
    variables {
      ami_id           = step.create_base_infra.ami_ids["ubuntu"]["amd64"]
      vpc_id           = step.create_base_infra.vpc_id
      kms_key_arn      = step.create_base_infra.kms_key_arn
      private_key_path = var.aws_ssh_private_key_path
    }
  }

  // step "deploy_controller" {
  //   module     = module.nomad_job
  //   depends_on = [step.provision_nomad_cluster]
  //   variables {
  //     private_key_path = var.aws_ssh_private_key_path
  //     nomad_instances  = step.provision_nomad_cluster.instance_public_ips
  //   }
  // }

  step "provision_alb" {
    module = module.alb_boundary

    variables {
      vpc_subnets = step.create_base_infra.vpc_subnets
      vpc_id = step.create_base_infra.vpc_id
      cidr_blocks = step.provision_nomad_cluster.cidr_blocks
      instance_ids = step.provision_nomad_cluster.instance_ids
    }
  }
}
