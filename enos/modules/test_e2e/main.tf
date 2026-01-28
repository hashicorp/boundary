# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "debug_no_run" {
  description = "If set, this module will not execute the tests so that you can still access environment variables"
  type        = bool
  default     = false
}
variable "test_package" {
  description = "Name of Go test package to run"
  type        = string
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
variable "max_page_size" {
  description = "Max allowed page size for pagination requests"
  type        = number
}
variable "local_boundary_dir" {
  description = "Local Path to boundary executable"
  type        = string
}
variable "target_user" {
  description = "SSH username for target"
  type        = string
  default     = ""
}
variable "aws_ssh_private_key_path" {
  description = "Local Path to key used to SSH onto created hosts"
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
variable "vault_addr_public" {
  description = "Public address to a vault instance"
  type        = string
  default     = ""
}
variable "vault_addr_private" {
  description = "Private address to a vault instance"
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
variable "aws_role_arn" {
  description = "AWS Role ARN that has access to bucket"
  type        = string
  default     = ""
}
variable "worker_tag_ingress" {
  type    = string
  default = ""
}
variable "worker_tag_isolated" {
  type    = string
  default = ""
}
variable "worker_tag_collocated" {
  type    = string
  default = ""
}
variable "worker_address" {
  type    = string
  default = ""
}
variable "test_timeout" {
  type    = string
  default = "20m"
}
variable "boundary_license" {
  type    = string
  default = ""
}

variable "target_rdp_domain_controller_addr" {
  description = "Address of RDP domain controller"
  type        = string
  default     = ""
}
variable "target_rdp_domain_controller_addr_ipv6" {
  description = "IPV6 ddress of RDP domain controller"
  type        = string
  default     = ""
}
variable "target_rdp_domain_controller_user" {
  description = "Username for RDP domain controller"
  type        = string
  default     = "Administrator"
}
variable "target_rdp_domain_controller_password" {
  description = "Password for RDP domain controller"
  type        = string
  default     = ""
}
variable "target_rdp_domain_controller_ssh_key" {
  description = "Path to the ssh key for the windows domain controller and worker"
  type        = string
  default     = ""
}
variable "target_rdp_member_server_addr" {
  description = "Address of RDP member server"
  type        = string
  default     = ""
}
variable "target_rdp_member_server_domain_hostname" {
  description = "Domain Name of RDP member server"
  type        = string
  default     = ""
}
variable "target_rdp_member_server_user" {
  description = "Username for RDP member server"
  type        = string
  default     = "Administrator"
}
variable "target_rdp_member_server_password" {
  description = "Password for RDP member server"
  type        = string
  default     = ""
}
variable "target_rdp_domain_name" {
  description = "Domain name of RDP targets"
  type        = string
  default     = ""
}
variable "target_rdp_server_version" {
  description = "Server version of rdp target"
  type        = string
  default     = ""
}
variable "client_version" {
  description = "Client version of RDP client"
  type        = string
  default     = ""
}
variable "client_ip_public" {
  description = "Public IP of the client machine"
  type        = string
  default     = ""
}
variable "client_username" {
  description = "Username for the client machine"
  type        = string
  default     = ""
}
variable "client_password" {
  description = "Password for the client machine"
  type        = string
  default     = ""
}
variable "client_test_dir" {
  description = "Directory on the client machine where tests will be run"
  type        = string
  default     = ""
}
variable "client_ssh_key" {
  description = "Path to the ssh key for the windows client"
  type        = string
  default     = ""
}
variable "controller_ip_public" {
  description = "public ip of the controller"
  type        = string
  default     = ""
}
variable "ip_version" {
  description = "ip version used to setup boundary instance, should be 4, 6, or dual"
  type        = string
  default     = "4"

  validation {
    condition     = contains(["4", "6", "dual"], var.ip_version)
    error_message = "ip_version must be one of: [4, 6, dual]"
  }
}

locals {
  aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
  aws_host_set_ips1        = jsonencode(var.aws_host_set_ips1)
  aws_host_set_ips2        = jsonencode(var.aws_host_set_ips2)
  package_name             = reverse(split("/", var.test_package))[0]
}

resource "enos_local_exec" "run_e2e_test" {
  environment = {
    E2E_TESTS                                    = "true"
    BOUNDARY_ADDR                                = var.alb_boundary_api_addr
    BOUNDARY_LICENSE                             = var.boundary_license
    E2E_PASSWORD_AUTH_METHOD_ID                  = var.auth_method_id
    E2E_PASSWORD_ADMIN_LOGIN_NAME                = var.auth_login_name
    E2E_PASSWORD_ADMIN_PASSWORD                  = var.auth_password
    E2E_TARGET_ADDRESS                           = var.target_address
    E2E_TARGET_PORT                              = var.target_port
    E2E_SSH_USER                                 = var.target_user
    E2E_SSH_KEY_PATH                             = local.aws_ssh_private_key_path
    E2E_SSH_CA_KEY                               = ""
    VAULT_ADDR                                   = var.vault_addr_public
    VAULT_TOKEN                                  = var.vault_root_token
    E2E_VAULT_ADDR_PUBLIC                        = var.vault_addr_public
    E2E_VAULT_ADDR_PRIVATE                       = var.vault_addr_private
    E2E_AWS_ACCESS_KEY_ID                        = var.aws_access_key_id
    E2E_AWS_SECRET_ACCESS_KEY                    = var.aws_secret_access_key
    E2E_AWS_HOST_SET_FILTER                      = var.aws_host_set_filter1
    E2E_AWS_HOST_SET_IPS                         = local.aws_host_set_ips1
    E2E_AWS_HOST_SET_FILTER2                     = var.aws_host_set_filter2
    E2E_AWS_HOST_SET_IPS2                        = local.aws_host_set_ips2
    E2E_AWS_REGION                               = var.aws_region
    E2E_AWS_BUCKET_NAME                          = var.aws_bucket_name
    E2E_AWS_ROLE_ARN                             = var.aws_role_arn
    E2E_WORKER_TAG_INGRESS                       = var.worker_tag_ingress
    E2E_WORKER_TAG_ISOLATED                      = var.worker_tag_isolated
    E2E_WORKER_TAG_COLLOCATED                    = var.worker_tag_collocated
    E2E_WORKER_ADDRESS                           = var.worker_address
    E2E_MAX_PAGE_SIZE                            = var.max_page_size
    E2E_IP_VERSION                               = var.ip_version
    E2E_TARGET_RDP_DOMAIN_CONTROLLER_ADDR        = var.target_rdp_domain_controller_addr
    E2E_TARGET_RDP_DOMAIN_CONTROLLER_ADDR_IPV6   = var.target_rdp_domain_controller_addr_ipv6
    E2E_TARGET_RDP_DOMAIN_CONTROLLER_USER        = var.target_rdp_domain_controller_user
    E2E_TARGET_RDP_DOMAIN_CONTROLLER_PASSWORD    = var.target_rdp_domain_controller_password
    E2E_TARGET_RDP_DOMAIN_CONTROLLER_SSH_KEY     = var.target_rdp_domain_controller_ssh_key
    E2E_TARGET_RDP_MEMBER_SERVER_ADDR            = var.target_rdp_member_server_addr
    E2E_TARGET_RDP_MEMBER_SERVER_DOMAIN_HOSTNAME = var.target_rdp_member_server_domain_hostname
    E2E_TARGET_RDP_MEMBER_SERVER_USER            = var.target_rdp_member_server_user
    E2E_TARGET_RDP_MEMBER_SERVER_PASSWORD        = var.target_rdp_member_server_password
    E2E_TARGET_RDP_DOMAIN_NAME                   = var.target_rdp_domain_name
    E2E_TARGET_RDP_SERVER_VERSION                = var.target_rdp_server_version
    E2E_CONTROLLER_IP_PUBLIC                     = var.controller_ip_public
    E2E_CLIENT_IP_PUBLIC                         = var.client_ip_public
    E2E_CLIENT_USERNAME                          = var.client_username
    E2E_CLIENT_PASSWORD                          = var.client_password
    E2E_CLIENT_TEST_DIR                          = var.client_test_dir
    E2E_CLIENT_VERSION                           = var.client_version
    E2E_CLIENT_SSH_KEY                           = var.client_ssh_key
  }

  inline = var.debug_no_run ? [""] : [
    "set -o pipefail; PATH=\"${var.local_boundary_dir}:$PATH\" go test -v ${var.test_package} -count=1 -timeout ${var.test_timeout} | tee ${path.module}/../../test-e2e-${local.package_name}.log"
  ]
}

output "test_results" {
  value = enos_local_exec.run_e2e_test.stdout
}
