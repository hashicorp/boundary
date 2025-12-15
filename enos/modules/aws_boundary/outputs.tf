# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

output "controller_ips" {
  description = "Public IPs of boundary controllers"
  value       = var.ip_version == "6" ? flatten(aws_instance.controller.*.ipv6_addresses) : aws_instance.controller.*.public_ip
}

output "controller_ips_private" {
  description = "Private IPs of boundary controllers"
  value       = var.ip_version == "6" || var.ip_version == "dual" ? flatten(aws_instance.controller.*.ipv6_addresses) : aws_instance.controller.*.private_ip
}

output "worker_ips" {
  description = "Public IPs of boundary workers"
  value       = var.ip_version == "6" ? flatten(aws_instance.worker.*.ipv6_addresses) : aws_instance.worker.*.public_ip
}

output "alb_hostname" {
  description = "Public hostname of Controller ALB"
  value       = aws_alb.boundary_alb.dns_name
}

output "rds_hostname" {
  description = "Public hostname of the RDS database"
  value       = var.db_create ? aws_db_instance.boundary[0].endpoint : var.db_host
}

output "rds_identifier" {
  description = "Unique identifier of the RDS database"
  value       = var.db_create ? aws_db_instance.boundary[0].identifier : null
}

output "rds_db_name" {
  description = "The name of the rds database created for the boundary cluster"
  value       = var.db_create ? aws_db_instance.boundary[0].db_name : null
}

output "alb_boundary_api_addr" {
  description = "The address of the boundary API"
  value       = var.protocol == "https" ? "https://${aws_alb.boundary_alb.dns_name}:${var.alb_listener_api_port}" : "http://${aws_alb.boundary_alb.dns_name}:${var.alb_listener_api_port}"
}

// Boundary init outputs
output "auth_method_id" {
  description = "Generated auth method id from boundary init"
  value       = try(enos_boundary_init.controller[0].auth_method_id, null)
}

output "auth_method_name" {
  description = "Generated auth method name from boundary init"
  value       = try(enos_boundary_init.controller[0].auth_method_name, null)
}

output "auth_login_name" {
  description = "Generated login name from boundary init"
  value       = try(enos_boundary_init.controller[0].auth_login_name, null)
}

output "auth_password" {
  description = "Generated auth password from boundary init"
  value       = try(enos_boundary_init.controller[0].auth_password, null)
}

output "auth_scope_id" {
  description = "Generated auth scope id from boundary init"
  value       = try(enos_boundary_init.controller[0].auth_scope_id, null)
}

output "auth_user_id" {
  description = "Generated user id from boundary init"
  value       = try(enos_boundary_init.controller[0].auth_user_id, null)
}

output "auth_user_name" {
  description = "Generated user naem from boundary init"
  value       = try(enos_boundary_init.controller[0].auth_user_name, null)
}

output "host_catalog_id" {
  description = "Generated host catalog id from boundary init"
  value       = try(enos_boundary_init.controller[0].host_catalog_id, null)
}

output "host_set_id" {
  description = "Generated host set id from boundary init"
  value       = try(enos_boundary_init.controller[0].host_set_id, null)
}

output "host_id" {
  description = "Generated host id from boundary init"
  value       = try(enos_boundary_init.controller[0].host_id, null)
}

output "host_type" {
  description = "Generated host type from boundary init"
  value       = try(enos_boundary_init.controller[0].host_type, null)
}

output "host_scope_id" {
  description = "Generated host scope id from boundary init"
  value       = try(enos_boundary_init.controller[0].host_scope_id, null)
}

output "host_catalog_name" {
  description = "Generated host catalog name from boundary init"
  value       = try(enos_boundary_init.controller[0].host_catalog_name, null)
}

output "host_set_name" {
  description = "Generated host set name from boundary init"
  value       = try(enos_boundary_init.controller[0].host_set_name, null)
}

output "host_name" {
  description = "Generated host name from boundary init"
  value       = try(enos_boundary_init.controller[0].host_name, null)
}

output "login_role_scope_id" {
  description = "Generated login role scope id from boundary init"
  value       = try(enos_boundary_init.controller[0].login_role_scope_id, null)
}

output "login_role_name" {
  description = "Generated login role name from boundary init"
  value       = try(enos_boundary_init.controller[0].login_role_name, null)
}

output "org_scope_id" {
  description = "Generated org scope id from boundary init"
  value       = try(enos_boundary_init.controller[0].org_scope_id, null)
}

output "org_scope_type" {
  description = "Generated org scope type from boundary init"
  value       = try(enos_boundary_init.controller[0].org_scope_type, null)
}

output "org_scope_name" {
  description = "Generated org scope name from boundary init"
  value       = try(enos_boundary_init.controller[0].org_scope_name, null)
}

output "project_scope_id" {
  description = "Generated project scope id from boundary init"
  value       = try(enos_boundary_init.controller[0].project_scope_id, null)
}

output "project_scope_type" {
  description = "Generated project scope type from boundary init"
  value       = try(enos_boundary_init.controller[0].project_scope_type, null)
}

output "project_scope_name" {
  description = "Generated project scope name from boundary init"
  value       = try(enos_boundary_init.controller[0].project_scope_name, null)
}

output "max_page_size" {
  value = var.max_page_size
}

output "target_id" {
  description = "Generated target id from boundary init"
  value       = try(enos_boundary_init.controller[0].target_id, null)
}

output "target_default_port" {
  description = "Generated target default port from boundary init"
  value       = try(enos_boundary_init.controller[0].target_default_port, null)
}

output "target_session_max_seconds" {
  description = "Generated target session max from boundary init"
  value       = try(enos_boundary_init.controller[0].target_session_max_seconds, null)
}

output "target_session_connection_limit" {
  description = "Generated target session connection limit from boundary init"
  value       = try(enos_boundary_init.controller[0].target_session_connection_limit, null)
}

output "target_type" {
  description = "Generated target type from boundary init"
  value       = try(enos_boundary_init.controller[0].target_type, null)
}

output "target_scope_id" {
  description = "Generated target scope id from boundary init"
  value       = try(enos_boundary_init.controller[0].target_scope_id, null)
}

output "target_name" {
  description = "Generated target name from boundary init"
  value       = try(enos_boundary_init.controller[0].target_name, null)
}

output "iam_instance_profile_name" {
  description = "The name of the IAM instance profile used with this cluster"
  value       = aws_iam_instance_profile.boundary_profile.name
}


output "name_prefix" {
  description = "The prefix used when naming this cluster's components"
  value       = local.name_prefix
}

output "cluster_tag" {
  description = "The tag for this cluster"
  value       = local.boundary_cluster_tag
}

output "public_controller_addresses" {
  value = var.ip_version == "4" ? aws_instance.controller[*].public_ip : aws_instance.controller[*].ipv6_addresses[0]
}

output "boundary_sg_id" {
  description = "A secruity group id that covers basic boundary ports and ssh"
  value       = aws_security_group.boundary_sg.id
}

output "controller_aux_sg_id" {
  description = "A security group ID that covers the controllers for adding extra rules to"
  value       = aws_security_group.boundary_aux_sg.id
}

output "subnet_ids" {
  description = "A list of the subnets created by the infra modules to share with other modules"
  value       = tolist(data.aws_subnets.infra.ids)
}

output "pet_id" {
  description = "The ID of the random_pet used in this module"
  value       = random_pet.default.id
}

output "worker_tokens" {
  description = "If available, worker tokens used to register to Boundary"
  value = try([
    for token in enos_remote_exec.get_worker_token : trimspace(token.stdout)
  ], null)
}

output "worker_cidr" {
  description = "List of ipv4 subnets of all workers"
  value       = formatlist("%s/32", aws_instance.worker.*.public_ip)
}

output "worker_ipv6_cidr" {
  description = "List of ipv6 subnets of all workers"
  value       = distinct([for ip in flatten(aws_instance.worker.*.ipv6_addresses) : cidrsubnet("${ip}/64", 0, 0)])
}

output "alb_cert" {
  description = "Public cert for the alb"
  value       = try(tls_self_signed_cert.certificate[0].cert_pem, null)
}