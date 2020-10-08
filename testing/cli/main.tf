terraform {
  required_providers {
    boundary = {
      source  = "localhost/providers/boundary"
      version = "0.0.1"
    }
  }
}

provider "boundary" {
  addr                            = "http://127.0.0.1:9200"
  auth_method_id                  = "ampw_1234567890"
  password_auth_method_login_name = "admin"
  password_auth_method_password   = "password"
}

variable "default_host_set" {
  default = "hsst_1234567890"
}

variable "default_project_id" {
  default = "p_1234567890"
}

variable "default_org_id" {
  default = "o_1234567890"
}

variable "default_auth_method_id" {
  default = "ampw_1234567890"
}

variable "users" {
  type = set(string)
  default = [
    "jim",
    "mike",
    "todd",
    "randy",
    "susmitha",
    "jeff",
    "pete",
    "harold",
  ]
}

resource "boundary_user" "user" {
  for_each    = var.users
  name        = each.key
  description = "User resource for ${each.key}"
  account_ids = [boundary_account.user[each.value].id]
  scope_id    = "global"
}

resource "boundary_account" "user" {
  for_each       = var.users
  name           = each.key
  description    = "User account for ${each.key}"
  type           = "password"
  login_name     = lower(each.key)
  password       = "foofoofoo"
  auth_method_id = var.default_auth_method_id
}

resource "boundary_role" "org_admin" {
  scope_id       = "global"
  grant_scope_id = var.default_org_id
  grant_strings  = ["id=*;type=*;actions=*"]
  principal_ids = concat(
    [for user in boundary_user.user : user.id],
    ["u_auth"]
  )
}

resource "boundary_role" "proj_admin" {
  scope_id       = var.default_org_id
  grant_scope_id = var.default_project_id
  grant_strings  = ["id=*;type=*;actions=*"]
  principal_ids = concat(
    [for user in boundary_user.user : user.id],
    ["u_auth"]
  )
}

resource "boundary_target" "postgres" {
  type                     = "tcp"
  name                     = "postgres"
  description              = "Postgres server"
  scope_id                 = var.default_project_id
  session_connection_limit = -1
  session_max_seconds      = 2
  default_port             = 5432
  host_set_ids = [
    var.default_host_set
  ]
}

resource "boundary_target" "cassandra" {
  type                     = "tcp"
  name                     = "cassandra"
  description              = "Cassandra server"
  scope_id                 = var.default_project_id
  session_connection_limit = -1
  session_max_seconds      = 2
  default_port             = 7000
  host_set_ids = [
    var.default_host_set
  ]
}
resource "boundary_target" "ssh" {
  type                     = "tcp"
  name                     = "ssh"
  description              = "SSH server"
  scope_id                 = var.default_project_id
  session_connection_limit = -1
  session_max_seconds      = 2
  default_port             = 22
  host_set_ids = [
    var.default_host_set
  ]
}
