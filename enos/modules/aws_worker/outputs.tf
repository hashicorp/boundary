# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

output "worker_ip" {
  description = "The public IP of the Boundary worker"
  value       = var.ip_version == "6" ? format("[%s]", aws_instance.worker.ipv6_addresses[0]) : aws_instance.worker.public_ip
}

output "worker_upstream_ips" {
  description = "List of ips that workers can use to reach upstream workers"
  value       = var.ip_version == "4" ? [for ip in aws_instance.worker.*.private_ip : "${ip}:9202"] : [for ip in flatten(aws_instance.worker.*.ipv6_addresses) : "[${ip}]:9201"]
}

output "worker_tags" {
  description = "The tags used in the worker's configuration"
  value       = var.worker_type_tags
}

output "subnet_ids" {
  description = "The ID of the subnet this worker resides in"
  value       = length(var.subnet_ids) == 0 ? [aws_subnet.default[0].id] : var.subnet_ids
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
  value       = var.ip_version == "6" ? [] : length(var.subnet_ids) == 0 ? [aws_subnet.default[0].cidr_block] : []
}

output "worker_ipv6_cidr" {
  description = "The ipv6 subnet of the isolated worker"
  value       = var.ip_version == "4" ? [] : length(var.subnet_ids) == 0 ? [aws_subnet.default[0].ipv6_cidr_block] : []
}
