# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform_cli "default" {
  plugin_cache_dir = abspath("./terraform-plugin-cache")
}

terraform "default" {
  required_version = ">= 1.0.0"

  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }

    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" "default" {
  region = var.aws_region
}

provider "enos" "default" {
  transport = {
    ssh = {
      user             = "ubuntu"
      private_key_path = abspath(var.aws_ssh_private_key_path)
    }
  }
}
