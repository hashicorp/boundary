# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "debug_no_run" {
  description = "If set, this module will not execute the tests so that you can still access environment variables"
  type        = bool
  default     = true
}
variable "alb_boundary_api_addr" {
  description = "URL of the Boundary instance"
  type        = string
  default     = ""
}
variable "auth_method_id" {
  description = "Id of Auth Method used to login to Boundary instance"
  type        = string
  default     = ""
}
variable "auth_login_name" {
  description = "Name of admin user"
  type        = string
  default     = ""
}
variable "auth_password" {
  description = "Password of admin user"
  type        = string
  default     = ""
}
variable "local_boundary_dir" {
  description = "Local Path to boundary executable"
  type        = string
}
variable "local_boundary_ui_src_dir" {
  description = "Local Path to boundary-ui directory"
  type        = string
}

variable "aws_ssh_private_key_path" {
  description = "Local Path to key used to SSH onto created hosts"
  type        = string
  default     = ""
}
variable "target_user" {
  description = "SSH username for target"
  type        = string
  default     = ""
}
variable "target_address" {
  description = "Address of target"
  type        = string
  default     = ""
}
variable "target_port" {
  description = "Port of target"
  type        = string
  default     = ""
}
variable "target_ca_key" {
  description = "CA Private Key (base64 encoded)"
  type        = string
  default     = ""
}
variable "target_ca_key_public" {
  description = "CA Public Key (base64 encoded)"
  type        = string
  default     = ""
}
variable "vault_addr" {
  description = "External network address of Vault. Will be converted to a URL below"
  type        = string
  default     = ""
}
variable "vault_addr_internal" {
  description = "Internal network address of Vault (i.e. within a docker network). Will be converted to a URL below"
  type        = string
  default     = ""
}
variable "vault_root_token" {
  description = "Root token for vault instance"
  type        = string
  default     = ""
}
variable "vault_port" {
  description = "External Port that vault instance is attached to (outside of docker network)"
  type        = string
  default     = "8200"
}
variable "aws_access_key_id" {
  description = "Access Key Id for AWS IAM user used in dynamic host catalogs"
  type        = string
  default     = ""
}
variable "aws_secret_access_key" {
  description = "Secret Access Key for AWS IAM user used in dynamic host catalogs"
  type        = string
  default     = ""
}
variable "aws_host_set_filter" {
  description = "Filter tag for host set used in dynamic host catalogs"
  type        = string
  default     = ""
}
variable "aws_region" {
  description = "AWS region where the resources will be created"
  type        = string
  default     = ""
}
variable "aws_bucket_name" {
  description = "AWS S3 bucket name"
  type        = string
  default     = ""
}
variable "aws_host_set_ips" {
  description = "List of IP addresses in aws_host_set_filter1"
  type        = list(string)
  default     = [""]
}
variable "ldap_address" {
  description = "URL to LDAP server"
  type        = string
  default     = ""
}
variable "ldap_domain_dn" {
  description = "Distinguished Name to the LDAP domain"
  type        = string
  default     = ""
}
variable "ldap_admin_dn" {
  description = "Distinguished Name to the LDAP admin user"
  type        = string
  default     = ""
}
variable "ldap_admin_password" {
  description = "Password for the LDAP admin user"
  type        = string
  default     = ""
}
variable "ldap_user_name" {
  description = "Username of an LDAP user"
  type        = string
  default     = ""
}
variable "ldap_user_password" {
  description = "Password for an LDAP user"
  type        = string
  default     = ""
}
variable "ldap_group_name" {
  description = "Name of LDAP group"
  type        = string
  default     = ""
}
variable "worker_token" {
  description = "Worker Registration Token"
  type        = string
  default     = ""
}
variable "worker_tag_egress" {
  description = "Worker tag for the egress worker"
  type        = string
  default     = ""
}

locals {
  aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
  vault_addr               = var.vault_addr != "" ? "http://${var.vault_addr}:${var.vault_port}" : ""
  vault_addr_internal      = var.vault_addr_internal != "" ? "http://${var.vault_addr_internal}:8200" : local.vault_addr
  aws_host_set_ips         = jsonencode(var.aws_host_set_ips)
}

resource "enos_local_exec" "run_e2e_test" {
  environment = {
    BOUNDARY_ADDR                 = var.alb_boundary_api_addr
    E2E_PASSWORD_AUTH_METHOD_ID   = var.auth_method_id
    E2E_PASSWORD_ADMIN_LOGIN_NAME = var.auth_login_name
    E2E_PASSWORD_ADMIN_PASSWORD   = var.auth_password
    E2E_TARGET_ADDRESS            = var.target_address
    E2E_TARGET_PORT               = var.target_port
    E2E_SSH_USER                  = var.target_user
    E2E_SSH_KEY_PATH              = local.aws_ssh_private_key_path
    E2E_SSH_CA_KEY                = var.target_ca_key
    E2E_SSH_CA_KEY_PUBLIC         = var.target_ca_key_public
    VAULT_ADDR                    = local.vault_addr
    VAULT_TOKEN                   = var.vault_root_token
    E2E_VAULT_ADDR                = local.vault_addr_internal
    E2E_AWS_ACCESS_KEY_ID         = var.aws_access_key_id
    E2E_AWS_SECRET_ACCESS_KEY     = var.aws_secret_access_key
    E2E_AWS_HOST_SET_FILTER       = var.aws_host_set_filter
    E2E_AWS_HOST_SET_IPS          = local.aws_host_set_ips
    E2E_AWS_REGION                = var.aws_region
    E2E_AWS_BUCKET_NAME           = var.aws_bucket_name
    E2E_LDAP_ADDR                 = var.ldap_address
    E2E_LDAP_DOMAIN_DN            = var.ldap_domain_dn
    E2E_LDAP_ADMIN_DN             = var.ldap_admin_dn
    E2E_LDAP_ADMIN_PASSWORD       = var.ldap_admin_password
    E2E_LDAP_USER_NAME            = var.ldap_user_name
    E2E_LDAP_USER_PASSWORD        = var.ldap_user_password
    E2E_LDAP_GROUP_NAME           = var.ldap_group_name
    E2E_WORKER_TOKEN              = var.worker_token
    E2E_WORKER_TAG_EGRESS         = var.worker_tag_egress
  }

  inline = var.debug_no_run ? [""] : ["set -o pipefail; PATH=\"${var.local_boundary_dir}:$PATH\" yarn --cwd ${var.local_boundary_ui_src_dir}/ui/admin run e2e 2>&1 | tee ${path.module}/../../test-e2e-ui.log"]
}

output "test_results" {
  value = enos_local_exec.run_e2e_test.stdout
}
