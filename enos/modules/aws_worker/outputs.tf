# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

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

output "pet_id" {
  description = "The ID of the random_pet used in this module"
  value       = random_pet.worker.id
}
