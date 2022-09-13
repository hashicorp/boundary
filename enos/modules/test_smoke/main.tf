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
variable "aws_ssh_private_key_path" {}
variable "boundary_install_dir" {}
variable "controller_ips" {}
variable "local_boundary_dir" {}
variable "project_scope_id" {}
variable "target_count" {}
variable "target_id" {}
variable "target_ips" {}

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

locals {
  base_environment = {
    BOUNDARY_ADDR  = var.alb_boundary_api_addr,
    BOUNDARY_TOKEN = local.auth_token
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
  auth_token = jsondecode(enos_local_exec.get_token.stdout).item.attributes.token
}

resource "enos_local_exec" "read_target" {
  environment = local.base_environment
  inline      = ["${var.local_boundary_dir}/boundary targets read -id ${var.target_id}"]
}

resource "enos_local_exec" "create_catalog" {
  environment = local.base_environment
  inline      = ["${var.local_boundary_dir}/boundary host-catalogs create static -scope-id=${var.project_scope_id} -name=enos1 -description=test -format=json"]
}

locals {
  catalog_id = jsondecode(enos_local_exec.create_catalog.stdout).item.id
}

resource "enos_local_exec" "create_static_hosts" {
  environment = local.base_environment
  for_each    = toset([for idx in range(var.target_count) : tostring(idx)])
  inline      = ["${var.local_boundary_dir}/boundary hosts create static -name=${var.target_ips[each.value]} -description=${var.target_ips[each.value]} -address=${var.target_ips[each.value]} -host-catalog-id=${local.catalog_id} -format=json"]
}

locals {
  host_ids = [for idx in range(var.target_count) : jsondecode(values(enos_local_exec.create_static_hosts)[idx].stdout).item.id]
}

resource "enos_local_exec" "create_host_set" {
  environment = local.base_environment
  inline      = ["${var.local_boundary_dir}/boundary host-sets create static -name='test-machines' -description='Test machine host set' -host-catalog-id=${local.catalog_id} -format=json"]
}

locals {
  host_set_id = jsondecode(enos_local_exec.create_host_set.stdout).item.id
}

resource "enos_local_exec" "add_to_host_set" {
  environment = local.base_environment
  for_each    = toset([for idx in range(var.target_count) : tostring(idx)])
  inline      = ["${var.local_boundary_dir}/boundary host-sets add-hosts -id=${local.host_set_id} -host=${local.host_ids[each.value]} -format=json"]
}

resource "enos_local_exec" "create_target" {
  environment = local.base_environment
  inline      = ["${var.local_boundary_dir}/boundary targets create tcp -name='test target' -description='test target' -default-port=22 -scope-id=${var.project_scope_id} -session-connection-limit='-1' -session-max-seconds=900 -format=json"]
}

locals {
  target_id = jsondecode(enos_local_exec.create_target.stdout).item.id
}

resource "enos_local_exec" "add_hosts_to_target" {
  environment = local.base_environment
  inline      = ["${var.local_boundary_dir}/boundary targets add-host-sources -id=${local.target_id} -host-source=${local.host_set_id} -format=json"]
}

resource "enos_local_exec" "connect_target" {
  environment = merge(local.base_environment,
    {
      BOUNDARY_PATH = var.local_boundary_dir
      TARGET_ID     = local.target_id
      SSH_KEY_PATH  = var.aws_ssh_private_key_path
      SSH_USER      = "ubuntu"
  })
  scripts = ["${path.module}/../../templates/connect-target.sh"]
}
