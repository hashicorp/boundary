# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    external = {
      source = "hashicorp/external"
    }
  }
}

data "external" "repo_root" {
  program = ["bash", "-c", "printf '{\"path\":\"%s\"}' \"$(git rev-parse --show-toplevel)\""]
}

data "external" "make_edition" {
  program = ["bash", "-c", "edition=$(make -s -C '${data.external.repo_root.result.path}' edition | tr -d '\\r\\n') && printf '{\"edition\":\"%s\"}' \"$edition\""]
}

output "edition" {
  value = data.external.make_edition.result.edition
}


