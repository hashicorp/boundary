# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform_cli "default" {
  plugin_cache_dir = abspath("./terraform-plugin-cache")

  credentials "app.terraform.io" {
    token = var.tfc_api_token
  }
}

terraform "default" {
  required_version = ">= 1.0.0"

  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
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
      private_key_path = abspath(var.aws_ssh_private_key_path)
    }
  }
}
