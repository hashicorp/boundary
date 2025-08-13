# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

// This is the public DNS address of our instance
output "public_dns_address" {
  value = aws_instance.worker.public_dns
}

output "public_ip" {
  value = aws_instance.worker.public_ip
}

output "public_ip_list" {
  value = [aws_instance.worker.public_ip]
}

output "private_ip" {
  value = aws_instance.worker.private_ip
}

output "admin_username" {
  description = "The username of the administrator account"
  value       = "Administrator"
}

// This is the decrypted administrator password for the EC2 instance
output "admin_password" {
  description = "Decrpted admin password for the EC2 instance"
  value       = nonsensitive(local.admin_password)
}