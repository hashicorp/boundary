terraform {
  required_providers {
    # We need to specify the provider source in each module until we publish it
    # to the public registry
    enos = {
      version = ">= 0.1.28"
      source  = "hashicorp.com/qti/enos"
    }
  }
}

data "enos_environment" "localhost" {}

resource "random_string" "cluster_id" {
  length  = 8
  lower   = true
  upper   = false
  numeric = false
  special = false
}
