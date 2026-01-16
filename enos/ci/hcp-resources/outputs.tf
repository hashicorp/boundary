# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

output "bucket_access_key_id" {
  value = module.iam_user.access_key_id
}

output "bucket_secret_access_key" {
  sensitive = true
  value     = module.iam_user.secret_access_key
}

output "bucket_name" {
  value = module.storage_bucket.bucket_name
}

output "host_set_filter" {
  value = module.target_tags.tag_string
}

output "target_public_ip" {
  value = module.target.target_public_ips
}

output "target_private_ip" {
  value = module.target.target_private_ips
}

output "target_ssh_user" {
  value = "ubuntu"
}

output "worker_ip" {
  value = module.worker.worker_ips
}

output "worker_tokens" {
  sensitive = true
  value     = module.worker.worker_tokens
}

output "region" {
  value = var.aws_region
}
