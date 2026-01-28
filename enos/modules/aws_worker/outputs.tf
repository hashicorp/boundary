# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

output "worker_ip" {
  description = "The public IP of the Boundary worker"
  value       = var.ip_version == "6" ? format("[%s]", aws_instance.worker.ipv6_addresses[0]) : aws_instance.worker.public_ip
}

output "worker_tags" {
  description = "The tags used in the worker's configuration"
  value       = var.worker_type_tags
}

output "subnet_ids" {
  description = "The ID of the subnet this worker resides in"
  value       = [aws_subnet.default.id]
}

output "pet_id" {
  description = "The ID of the random_pet used in this module"
  value       = random_pet.worker.id
}

output "role_arn" {
  description = "The ARN of the IAM role used in this module"
  value       = aws_iam_role.boundary_instance_role.arn
}

output "worker_cidr" {
  description = "The subnet of the isolated worker"
  value       = var.ip_version == "6" ? [] : [aws_subnet.default.cidr_block]
}

output "worker_ipv6_cidr" {
  description = "The ipv6 subnet of the isolated worker"
  value       = var.ip_version == "4" ? [] : [aws_subnet.default.ipv6_cidr_block]
}
