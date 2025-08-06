# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "public_dns_address" {
  value = aws_instance.rdp_target.public_dns
}

output "public_ip" {
  value = aws_instance.rdp_target.public_ip
}

output "private_ip" {
  value = aws_instance.rdp_target.private_ip
}

output "admin_username" {
  description = "The username of the administrator account"
  value       = "Administrator"
}

output "password" {
  description = "This is the decrypted administrator password for the EC2 instance"
  value       = nonsensitive(local.password)
}

output "ipv6" {
  value = flatten(aws_instance.rdp_target.*.ipv6_addresses)
}