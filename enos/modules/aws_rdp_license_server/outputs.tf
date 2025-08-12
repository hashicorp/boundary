# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "public_dns_address" {
  description = "This is the public DNS address of our instance"
  value       = aws_instance.license_server.public_dns
}

output "public_ip" {
  value = aws_instance.license_server.public_ip
}

output "admin_username" {
  description = "The username of the administrator account"
  value       = "Administrator"
}

output "password" {
  description = "This is the decrypted administrator password for the EC2 instance"
  value       = local.password
}
