terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "test_package" {
  description = "Name of Go test package to run"
  type        = string
}
variable "alb_boundary_api_addr" {
  description = "URL of the Boundary instance"
  type        = string
}
variable "auth_method_id" {
  description = "Id of Auth Method used to login to Boundary instance"
  type        = string
}
variable "auth_login_name" {
  description = "Name of admin user"
  type        = string
}
variable "auth_password" {
  description = "Password of admin user"
  type        = string
}
variable "local_boundary_dir" {
  description = "Local Path to boundary executable"
  type        = string
}
variable "target_user" {
  description = "SSH username for target"
  type        = string
}
variable "aws_ssh_private_key_path" {
  description = "Local Path to key used to SSH onto created hosts"
  type        = string
}
variable "target_ip" {
  description = "IP address of target"
  type        = string
  default     = ""
}
variable "vault_addr" {
  description = "URL of Vault instance"
  type        = string
  default     = ""
}
variable "vault_root_token" {
  description = "Root token for vault instance"
  type        = string
  default     = ""
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
variable "aws_host_set_filter1" {
  description = "Filter tag for host set used in dynamic host catalogs"
  type        = string
  default     = ""
}
variable "aws_host_set_count1" {
  description = "Number of hosts in aws_host_set_filter1"
  type        = number
  default     = 0
}
variable "aws_host_set_ips1" {
  description = "List of IP addresses in aws_host_set_filter1"
  type        = list(string)
  default     = [""]
}
variable "aws_host_set_filter2" {
  description = "Filter tag for host set used in dynamic host catalogs"
  type        = string
  default     = ""
}
variable "aws_host_set_ips2" {
  description = "List of IP addresses in aws_host_set_filter2"
  type        = list(string)
  default     = [""]
}

locals {
  aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
  vault_addr               = var.vault_addr != "" ? "http://${var.vault_addr}:8200" : ""
  aws_host_set_ips1        = jsonencode(var.aws_host_set_ips1)
  aws_host_set_ips2        = jsonencode(var.aws_host_set_ips2)
}

resource "enos_local_exec" "run_e2e_test" {
  environment = {
    BOUNDARY_ADDR                 = var.alb_boundary_api_addr,
    E2E_PASSWORD_AUTH_METHOD_ID   = var.auth_method_id,
    E2E_PASSWORD_ADMIN_LOGIN_NAME = var.auth_login_name,
    E2E_PASSWORD_ADMIN_PASSWORD   = var.auth_password,
    E2E_TARGET_IP                 = var.target_ip,
    E2E_SSH_USER                  = var.target_user,
    E2E_SSH_KEY_PATH              = local.aws_ssh_private_key_path,
    VAULT_ADDR                    = local.vault_addr,
    VAULT_TOKEN                   = var.vault_root_token,
    E2E_AWS_ACCESS_KEY_ID         = var.aws_access_key_id,
    E2E_AWS_SECRET_ACCESS_KEY     = var.aws_secret_access_key,
    E2E_AWS_HOST_SET_FILTER1      = var.aws_host_set_filter1,
    E2E_AWS_HOST_SET_IPS1         = local.aws_host_set_ips1,
    E2E_AWS_HOST_SET_FILTER2      = var.aws_host_set_filter2,
    E2E_AWS_HOST_SET_IPS2         = local.aws_host_set_ips2
  }

  inline = ["PATH=\"${var.local_boundary_dir}:$PATH\" go test -v ${var.test_package}"]
}

output "test_results" {
  value = enos_local_exec.run_e2e_test.stdout
}
