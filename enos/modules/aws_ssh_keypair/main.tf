# Copyright IBM Corp. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
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

variable "local_aws_keypair_name" {
  type        = string
  description = "Name of the key pair in AWS of the uploaded key from local_key_path."
  default     = null
}

check "local_key_path_requires_local_aws_keypair_name" {
  assert {
    condition     = var.local_key_path == null || var.local_aws_keypair_name != null
    error_message = "local_aws_keypair_name must be provided when local_key_path is set."
  }
}

resource "tls_private_key" "ssh" {
  count     = var.local_key_path == null ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated" {
  count      = var.local_key_path == null ? 1 : 0
  key_name   = "ssh-key-enos-aws"
  public_key = tls_private_key.ssh[0].public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  count           = var.local_key_path == null ? 1 : 0
  content         = tls_private_key.ssh[0].private_key_pem
  filename        = "${path.root}/.terraform/tmp/${aws_key_pair.generated[0].key_name}"
  file_permission = "0400"
}

output "key_pair_name" {
  value = var.local_key_path != null ? var.local_aws_keypair_name : aws_key_pair.generated[0].key_name
}

output "private_key_path" {
  value = var.local_key_path != null ? abspath(var.local_key_path) : abspath(local_sensitive_file.private_key[0].filename)
}
