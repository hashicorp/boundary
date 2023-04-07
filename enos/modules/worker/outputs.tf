# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "worker_ip" {
  description = "The public IP of the Boundary worker"
  value       = aws_instance.worker.public_ip
}

output "worker_tags" {
  description = "The tags used in the worker's configuration"
  value       = var.worker_type_tags
}

output "subnet_ids" {
  description = "The ID of the subnet this worker resides in"
  value       = [aws_subnet.default.id]
}
