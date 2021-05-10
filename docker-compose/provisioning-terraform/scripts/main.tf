provider "boundary" {
  addr                            = "http://boundary:9200"
  recovery_kms_hcl                = "/scripts/kms.hcl"
}


variable "backend_server_ips" {
  type    = set(string)
  default = [
    "ssh-testserver-01"
  ]
}

resource "boundary_account" "jeff" {
  auth_method_id = "ampw_1234567890"
  type           = "password"
  login_name     = "jeff"
  password       = "$uper$ecure"
}

resource "boundary_user" "jeff" {
  name        = "jeff"
  description = "Jeff's user resource"
  account_ids = [boundary_account.jeff.id]
  scope_id    = "global"
}

resource "boundary_user" "Demo1" {
  name        = "Demo1"
  description = "Demo1 user resource"
  account_ids = []
  scope_id    = "global"
}

// create a project for core infrastructure
resource "boundary_scope" "core_infra" {
  description              = "Core infrastrcture"
  name                     = "CoreInfra"
  scope_id                 = "o_1234567890"
  auto_create_admin_role   = true
}

resource "boundary_role" "core_infra_admin" {
  scope_id       = "o_1234567890"
  grant_scope_id = boundary_scope.core_infra.id
  grant_strings  = ["id=*;type=*;actions=*"]
  principal_ids  = ["u_1234567890"]
}

resource "boundary_host_catalog" "backend_servers" {
  name        = "backend_servers"
  description = "Backend servers host catalog"
  type        = "static"
  scope_id    = boundary_scope.core_infra.id
}

resource "boundary_host" "backend_servers" {
  for_each        = var.backend_server_ips
  type            = "static"
  name            = "backend_server_service_${each.value}"
  description     = "Backend server host"
  address         = "${each.key}"
  host_catalog_id = boundary_host_catalog.backend_servers.id
}

resource "boundary_host_set" "backend_servers_ssh" {
  type            = "static"
  name            = "backend_servers_ssh"
  description     = "Host set for backend servers"
  host_catalog_id = boundary_host_catalog.backend_servers.id
  host_ids        = [for host in boundary_host.backend_servers : host.id]
}

// create target for accessing backend servers on port :2222
resource "boundary_target" "backend_servers_ssh" {
  type         = "tcp"
  name         = "backend_servers_ssh"
  description  = "Backend SSH target"
  scope_id     = boundary_scope.core_infra.id
  default_port = "2222"

  host_set_ids = [
    boundary_host_set.backend_servers_ssh.id
  ]
}