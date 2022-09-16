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
variable "target_ips" {
  description = "List of IP Addresses of created hosts"
  type        = list(string)
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

locals {
  aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
  vault_addr               = var.vault_addr != "" ? "http://${var.vault_addr}:8200" : ""
}

resource "enos_local_exec" "run_e2e_test" {
  environment = {
    BOUNDARY_ADDR                 = var.alb_boundary_api_addr,
    E2E_PASSWORD_AUTH_METHOD_ID   = var.auth_method_id,
    E2E_PASSWORD_ADMIN_LOGIN_NAME = var.auth_login_name,
    E2E_PASSWORD_ADMIN_PASSWORD   = var.auth_password,
    E2E_TARGET_IP                 = var.target_ips[0],
    E2E_SSH_USER                  = var.target_user,
    E2E_SSH_KEY_PATH              = local.aws_ssh_private_key_path,
    VAULT_ADDR                    = local.vault_addr,
    VAULT_TOKEN                   = var.vault_root_token
  }

  inline = ["PATH=\"${var.local_boundary_dir}:$PATH\" go test -v ${var.test_package}"]
}

output "test_results" {
  value = enos_local_exec.run_e2e_test.stdout
}
