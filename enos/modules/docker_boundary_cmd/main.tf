# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "address" {
  description = "Address/URL to the Boundary controller/server"
  type        = string
}
variable "image_name" {
  description = "Name of docker image to use"
  type        = string
}
variable "network_name" {
  description = "Name of docker network to use"
  type        = string
}
variable "login_name" {
  description = "Login Name to log in to boundary"
  type        = string
}
variable "password" {
  description = "Password to log in to boundary"
  type        = string
}
variable "script" {
  description = "Filename of a script in the module directory to run"
  type        = string
}
variable "worker_token" {
  description = "Worker generated auth token"
  type        = string
  default     = ""
}

resource "enos_local_exec" "get_auth_token" {
  environment = {
    TEST_BOUNDARY_IMAGE           = var.image_name
    BOUNDARY_ADDR                 = var.address
    TEST_NETWORK_NAME             = var.network_name
    E2E_PASSWORD_ADMIN_LOGIN_NAME = var.login_name
    E2E_PASSWORD_ADMIN_PASSWORD   = var.password
    MODULE_DIR                    = abspath(path.module)
    SCRIPT                        = "${abspath(path.module)}/get_auth_token.sh"
  }
  inline = ["bash ./${path.module}/script_runner.sh"]
}

locals {
  auth_info  = jsondecode(enos_local_exec.get_auth_token.stdout)
  auth_token = local.auth_info["item"]["attributes"]["token"]
}

resource "enos_local_exec" "run_script" {
  depends_on = [enos_local_exec.get_auth_token]
  environment = {
    TEST_BOUNDARY_IMAGE           = var.image_name
    BOUNDARY_ADDR                 = var.address
    TEST_NETWORK_NAME             = var.network_name
    E2E_PASSWORD_ADMIN_LOGIN_NAME = var.login_name
    E2E_PASSWORD_ADMIN_PASSWORD   = var.password
    MODULE_DIR                    = abspath(path.module)
    SCRIPT                        = "${abspath(path.module)}/${var.script}"
    BOUNDARY_TOKEN                = local.auth_token
    WORKER_TOKEN                  = var.worker_token
  }
  inline = ["bash ./${path.module}/script_runner.sh"]
}

output "output" {
  value = jsondecode(enos_local_exec.run_script.stdout)
}
