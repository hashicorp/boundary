terraform {
  required_providers {
    enos = {
      source = "hashicorp.com/qti/enos"
    }
  }
}

module "ensure_bats" {
  source = "../binary_finder"
  name   = "bats"
}

module "ensure_jq" {
  source = "../binary_finder"
  name   = "jq"
}
