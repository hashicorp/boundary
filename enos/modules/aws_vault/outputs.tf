# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

output "instance_ids" {
  description = "IDs of Vault instances"
  value       = [for instance in aws_instance.vault_instance : instance.id]
}

output "instance_public_ips" {
  description = "Public IPs of Vault instances"
  value       = var.ip_version == "4" ? [for instance in aws_instance.vault_instance : instance.public_ip] : flatten([for instance in aws_instance.vault_instance : instance.ipv6_addresses])
}

output "instance_public_ips_ipv4" {
  description = "Public IPv4 addresses of Vault instances"
  value       = [for instance in aws_instance.vault_instance : instance.public_ip if instance.public_ip != null]
}

output "instance_private_ips" {
  description = "Private IPs of Vault instances"
  value       = [for instance in aws_instance.vault_instance : instance.private_ip]
}

output "instance_addresses" {
  description = "Addresses of Vault instances"
  value       = var.ip_version == "4" ? [for instance in aws_instance.vault_instance : "http://${instance.public_ip}:8200"] : flatten([for instance in aws_instance.vault_instance : instance.ipv6_addresses])
}

output "instance_addresses_private" {
  description = "Private addresses of Vault instances"
  value       = [for instance in aws_instance.vault_instance : "http://${instance.private_ip}:8200"]
}

output "key_id" {
  value = data.aws_kms_key.kms_key.id
}

output "vault_instances" {
  description = "The vault cluster instances that were created"

  value = {
    for instance in aws_instance.vault_instance : instance.id => {
      public_ip  = instance.public_ip
      private_ip = instance.private_ip
    }
  }
}

output "vault_root_token" {
  value = coalesce(var.vault_root_token, try(enos_vault_init.leader[0].root_token, null), "none")
}

output "vault_transit_token" {
  value = try([for token in enos_remote_exec.vault_kms_policy : trimspace(token.stdout)][0], "")
}

output "vault_unseal_keys_b64" {
  value = try(enos_vault_init.leader[0].unseal_keys_b64, [])
}

output "vault_unseal_keys_hex" {
  value = try(enos_vault_init.leader[0].unseal_keys_hex, null)
}

output "vault_unseal_shares" {
  value = try(enos_vault_init.leader[0].unseal_keys_shares, -1)
}

output "vault_unseal_threshold" {
  value = try(enos_vault_init.leader[0].unseal_keys_threshold, -1)
}

output "vault_recovery_keys_b64" {
  value = try(enos_vault_init.leader[0].recovery_keys_b64, [])
}

output "vault_recovery_keys_hex" {
  value = try(enos_vault_init.leader[0].recovery_keys_hex, [])
}

output "vault_recovery_key_shares" {
  value = try(enos_vault_init.leader[0].recovery_keys_shares, -1)
}

output "vault_recovery_threshold" {
  value = try(enos_vault_init.leader[0].recovery_keys_threshold, -1)
}

output "vault_cluster_tag" {
  description = "Cluster tag for Vault cluster"
  value       = local.vault_cluster_tag
}

output "audit_device_log_file_path" {
  description = "The path of the file audit device path, if enabled"
  value       = var.enable_file_audit_device ? local.audit_device_file_path : "no audit devices enabled"
}
