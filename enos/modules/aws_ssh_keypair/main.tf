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

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated" {
  key_name   = "enos-${var.enos_user}-${formatdate("YYYYMMDD-hhmmss", timestamp())}"
  public_key = tls_private_key.ssh.public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  content         = tls_private_key.ssh.private_key_pem
  filename        = "${path.root}/.terraform/tmp/ssh-key-${aws_key_pair.generated.key_name}"
  file_permission = "0400"
}

output "key_pair_name" {
  value = aws_key_pair.generated.key_name
}

output "private_key_path" {
  value = abspath(local_sensitive_file.private_key.filename)
}

output "private_key_pem" {
  value     = tls_private_key.ssh.private_key_pem
  sensitive = true
}