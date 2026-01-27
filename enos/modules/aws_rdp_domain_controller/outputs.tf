# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "public_dns_address" {
  value = aws_instance.domain_controller.public_dns
}

output "public_ip" {
  value = aws_instance.domain_controller.public_ip
}

output "private_ip" {
  value = aws_instance.domain_controller.private_ip
}

output "ipv6" {
  value = flatten(aws_instance.domain_controller.ipv6_addresses)
}

output "admin_username" {
  description = "The username of the administrator account"
  value       = "Administrator"
}

output "password" {
  description = "This is the decrypted administrator password for the EC2 instance"
  value       = nonsensitive(rsadecrypt(data.aws_instance.instance_password.password_data, tls_private_key.rsa_4096_key.private_key_pem))
}

output "ssh_private_key" {
  description = "Private key to ssh into the windows client"
  value       = abspath(local_sensitive_file.private_key.filename)
}

output "security_group_id_list" {
  description = "List of security group IDs attached to the RDP server"
  value       = aws_instance.domain_controller.vpc_security_group_ids
}

output "keypair_name" {
  description = "The name of the keypair used for the instance"
  value       = aws_key_pair.rdp-key.key_name
}

output "domain_name" {
  description = "The domain name the instance is joined to"
  value       = var.active_directory_domain
}

output "vault_ldap_user" {
  description = "User created for Vault LDAP use"
  value       = local.vault_ldap_user
}
