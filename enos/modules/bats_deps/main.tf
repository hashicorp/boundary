terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
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
