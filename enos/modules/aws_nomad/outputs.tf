output "instance_ids" {
  description = "IDs of Nomad instances"
  value       = [for instance in aws_instance.nomad_instance : instance.id]
}

output "instance_public_ips" {
  description = "Public IPs of Nomad instances"
  value       = [for instance in aws_instance.nomad_instance : instance.public_ip]
}

output "instance_private_ips" {
  description = "Private IPs of Nomad instances"
  value       = [for instance in aws_instance.nomad_instance : instance.private_ip]
}

output "key_id" {
  value = data.aws_kms_key.kms_key.id
}

output "nomad_cluster_tag" {
  description = "The Nomad cluster's cluster tag"
  value       = local.nomad_cluster_tag
}
