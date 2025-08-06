# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "public_dns_address" {
  description = "This is the public DNS address of our instance"
  value       = aws_instance.member_server.public_dns
}

output "public_ip" {
  value = aws_instance.member_server.public_ip
}

output "private_ip" {
  value = aws_instance.member_server.private_ip
}

output "ipv6" {
  value = flatten(aws_instance.member_server.ipv6_addresses)
}

output "admin_username" {
  description = "The username of the administrator account"
  value       = "Administrator"
}

output "password" {
  description = "This is the decrypted administrator password for the EC2 instance"
  value       = local.password
}

output "domain_hostname" {
  description = "The hostname of the domain controller"
  value       = trimspace(enos_local_exec.get_hostname.stdout)
}
