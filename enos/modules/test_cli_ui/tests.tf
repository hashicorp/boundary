# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "alb_boundary_api_addr" {}
variable "auth_login_name" {}
variable "auth_method_id" {}
variable "auth_password" {}
variable "auth_user_id" {}
variable "boundary_install_dir" {}
variable "controller_ips" {}
variable "host_catalog_id" {}
variable "host_id" {}
variable "host_set_id" {}
variable "local_boundary_dir" {}
variable "org_scope_id" {}
variable "project_scope_id" {}
variable "target_id" {}

resource "enos_local_exec" "local_boundary_version" {
  inline = ["${var.local_boundary_dir}/boundary version -format=json"]
}

resource "enos_remote_exec" "remote_boundary_version" {
  inline = ["${var.boundary_install_dir}/boundary version -format=json"]
  transport = {
    ssh = {
      host = var.controller_ips.0
    }
  }
}

resource "enos_local_exec" "get_token" {
  environment = {
    BOUNDARY_ADDR = var.alb_boundary_api_addr,
    BOUNDARY_PATH = var.local_boundary_dir,
    METHOD_ID     = var.auth_method_id,
    LOGIN_NAME    = var.auth_login_name,
    PASSWORD      = var.auth_password,
  }
  scripts = ["${path.module}/../../templates/get-token.sh"]
}

locals {
  auth_token    = jsondecode(enos_local_exec.get_token.stdout).item.attributes.token
  test_user     = "username123"
  test_password = var.auth_password
  base_environment = {
    BOUNDARY_ADDR  = var.alb_boundary_api_addr,
    BOUNDARY_TOKEN = local.auth_token
  }
}

resource "enos_local_exec" "create_account" {
  environment = {
    BOUNDARY_ADDR  = var.alb_boundary_api_addr,
    BOUNDARY_TOKEN = local.auth_token,
    BP             = local.test_password
  }
  inline = ["${var.local_boundary_dir}/boundary accounts create password -auth-method-id ${var.auth_method_id} -login-name ${local.test_user} -name ${local.test_user} -password env://BP -description 'test user' -format json"]
}

locals {
  account_id = jsondecode(enos_local_exec.create_account.stdout).item.id
}

resource "enos_local_exec" "create_user" {
  environment = local.base_environment
  inline      = ["${var.local_boundary_dir}/boundary users create -scope-id 'global' -name ${local.test_user} -description 'test user' -format json"]
}

locals {
  user_id = jsondecode(enos_local_exec.create_user.stdout).item.id
}

resource "enos_local_exec" "set_accounts" {
  environment = local.base_environment
  inline      = ["${var.local_boundary_dir}/boundary users set-accounts -id ${local.user_id} -account ${local.account_id}"]
}

resource "enos_local_exec" "get_role_id" {
  environment = local.base_environment
  inline      = ["${var.local_boundary_dir}/boundary roles list -scope-id=${var.project_scope_id} -format json"]
}

locals {
  # Get the role used for u_auth within the project
  role_id = jsondecode(enos_local_exec.get_role_id.stdout).items[1].id
}

resource "enos_local_exec" "add_grants" {
  depends_on  = [enos_local_exec.get_role_id]
  environment = local.base_environment
  inline      = ["${var.local_boundary_dir}/boundary roles add-grants -id=${local.role_id} -grant='id=*;type=target;actions=authorize-session' -format json"]
}


resource "enos_local_exec" "run_bats" {
  depends_on = [enos_local_exec.create_user]
  environment = {
    BOUNDARY_ADDR              = var.alb_boundary_api_addr,
    IS_VERSION                 = "true",
    DEFAULT_LOGIN              = "admin",
    DEFAULT_UNPRIVILEGED_LOGIN = local.test_user,
    DEFAULT_P_ID               = var.project_scope_id
    DEFAULT_O_ID               = var.org_scope_id
    DEFAULT_HOST_SET           = var.host_set_id
    DEFAULT_HOST_CATALOG       = var.host_catalog_id
    DEFAULT_HOST               = var.host_id
    DEFAULT_PASSWORD           = var.auth_password
    DEFAULT_TARGET             = var.target_id
    DEFAULT_AMPW               = var.auth_method_id
    DEFAULT_USER               = var.auth_user_id
    DEFAULT_UNPRIVILEGED_USER  = local.user_id
  }
  // TERM isn't set automatically in CI so we need to make sure it's always there.
  inline = ["TERM=\"$${TERM:=dumb}\" PATH=\"${var.local_boundary_dir}:$PATH\" bats -p ../../../internal/tests/cli/boundary"]
}
