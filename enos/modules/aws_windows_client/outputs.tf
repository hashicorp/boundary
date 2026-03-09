# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

// This is the public DNS address of our instance
output "public_dns_address" {
  value = aws_instance.client.public_dns
}

output "public_ip" {
  value = aws_instance.client.public_ip
}

output "public_ip_list" {
  value = [aws_instance.client.public_ip]
}

output "private_ip" {
  value = aws_instance.client.private_ip
}

output "admin_username" {
  description = "The username of the administrator account"
  value       = "Administrator"
}

// This is the decrypted administrator password for the EC2 instance
output "admin_password" {
  description = "The password for the administrator account"
  value       = nonsensitive(rsadecrypt(data.aws_instance.instance_password.password_data, tls_private_key.rsa-4096-key.private_key_pem))
}

output "test_username" {
  description = "The username of the test account"
  value       = local.test_username
}
output "test_password" {
  description = "The password of the test account"
  value       = nonsensitive(local.test_password)
}

output "test_dir" {
  description = "The directory where the test files are stored"
  value       = local.test_dir
}

output "ssh_private_key" {
  description = "Private key to ssh into the windows client"
  value       = abspath(local_sensitive_file.private_key.filename)
}