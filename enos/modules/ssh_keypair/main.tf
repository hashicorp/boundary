# Copyright IBM Corp. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    tls = {
      source = "hashicorp/tls"
    }
    local = {
      source = "hashicorp/local"
    }
  }
}

variable "local_key_path" {
  type        = string
  description = "Path to a local key. If provided, this key will be used instead of generating a new one."
  default     = null
}

resource "random_pet" "default" {}

resource "tls_private_key" "ssh" {
  count     = var.local_key_path == null ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_sensitive_file" "private_key" {
  count           = var.local_key_path == null ? 1 : 0
  content         = tls_private_key.ssh[0].private_key_pem
  filename        = "${path.root}/.terraform/tmp/ssh-key-enos-${random_pet.default.id}"
  file_permission = "0400"
}

output "private_key_path" {
  value = var.local_key_path != null ? abspath(var.local_key_path) : abspath(local_sensitive_file.private_key[0].filename)
}
