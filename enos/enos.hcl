# Copyright IBM Corp. 2020, 2025
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
      source  = "hashicorp/aws"
      version = "5.72.1"
    }

    google = {
      source  = "hashicorp/google"
      version = "5.22.0"
    }
  }
}

provider "aws" "default" {
  region = var.aws_region
}

provider "enos" "default" {
  transport = {
    ssh = {
      user = "ubuntu"
    }
  }
}

provider "google" "default" {
  region  = var.gcp_region
  project = var.gcp_project_id
}
