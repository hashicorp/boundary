# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.1"
    }

    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
    }
  }
}

variable "docker_mirror" {
  description = "URL to the docker repository"
  type        = string
}
variable "network_name" {
  description = "Name of Docker Network"
  type        = string
}
variable "controller_container_name" {
  description = "Name of Docker Container running the Boundary controller"
  type        = string
  default     = ""
}
variable "go_version" {
  description = "Version of Golang used by the application under test"
  type        = string
  default     = ""
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
variable "local_boundary_dir" {
  description = "Local Path to boundary executable"
  type        = string
}
variable "local_boundary_src_dir" {
  description = "Local Path to boundary src code directory"
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
variable "target_ca_key" {
  description = "CA Private Key (base64 encoded)"
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
variable "access_key_id" {
  description = "Access Key Id for AWS IAM user used in dynamic host catalogs"
  type        = string
  default     = ""
}
variable "secret_access_key" {
  description = "Secret Access Key for AWS IAM user used in dynamic host catalogs"
  type        = string
  default     = ""
}
variable "region" {
  description = "AWS region where the resources will be created"
  type        = string
  default     = ""
}
variable "bucket_name" {
  description = "Storage bucket name"
  type        = string
  default     = ""
}
variable "minio_alias" {
  description = "Alias used in the minio cli"
  type        = string
  default     = ""
}
variable "bucket_endpoint_url" {
  description = "Endpoint URL for the storage bucket"
  type        = string
  default     = ""
}
variable "worker_tag_ingress" {
  description = "Worker tag for the ingress worker"
  type        = string
  default     = ""
}
variable "worker_tag_egress" {
  description = "Worker tag for the egress worker"
  type        = string
  default     = ""
}
variable "worker_tag_collocated" {
  description = "Worker tag for the collocated worker"
  type        = string
  default     = ""
}
variable "max_page_size" {
  description = "Max allowed page size for pagination requests"
  type        = number
}
variable "postgres_user" {
  description = "Username for accessing the postgres database"
  type        = string
  default     = ""
}
variable "postgres_password" {
  description = "Password for accessing the postgres database"
  type        = string
  default     = ""
}
variable "postgres_database_name" {
  description = "Name of postgres database"
  type        = string
  default     = ""
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
variable "test_timeout" {
  type    = string
  default = "25m"
}

resource "enos_local_exec" "get_go_version" {
  count  = var.go_version == "" ? 1 : 0
  inline = ["cat $(echo $(git rev-parse --show-toplevel))/.go-version | xargs"]
}

locals {
  go_version = var.go_version == "" ? enos_local_exec.get_go_version[0].stdout : var.go_version
  image_name = trimspace("${var.docker_mirror}/library/golang:${local.go_version}")

  aws_ssh_private_key_path = abspath(var.aws_ssh_private_key_path)
  vault_addr               = var.vault_addr != "" ? "http://${var.vault_addr}:${var.vault_port}" : ""
  vault_addr_internal      = var.vault_addr_internal != "" ? "http://${var.vault_addr_internal}:8200" : local.vault_addr
  package_name             = reverse(split("/", var.test_package))[0]
}

resource "docker_image" "go" {
  name         = local.image_name
  keep_locally = true
}

resource "enos_local_exec" "run_e2e_test" {
  depends_on = [docker_image.go]
  environment = {
    TEST_PACKAGE                  = var.test_package
    TEST_TIMEOUT                  = var.test_timeout
    TEST_RUNNER_IMAGE             = docker_image.go.image_id
    TEST_NETWORK_NAME             = var.network_name
    E2E_TESTS                     = "true"
    BOUNDARY_ADDR                 = var.alb_boundary_api_addr
    E2E_PASSWORD_AUTH_METHOD_ID   = var.auth_method_id
    E2E_PASSWORD_ADMIN_LOGIN_NAME = var.auth_login_name
    E2E_PASSWORD_ADMIN_PASSWORD   = var.auth_password
    E2E_TARGET_ADDRESS            = var.target_address
    E2E_TARGET_PORT               = var.target_port
    E2E_SSH_USER                  = var.target_user
    E2E_SSH_KEY_PATH              = local.aws_ssh_private_key_path
    E2E_SSH_CA_KEY                = var.target_ca_key
    VAULT_ADDR                    = local.vault_addr
    VAULT_ADDR_INTERNAL           = local.vault_addr_internal
    VAULT_TOKEN                   = var.vault_root_token
    E2E_VAULT_ADDR                = local.vault_addr_internal
    E2E_BUCKET_NAME               = var.bucket_name
    E2E_BUCKET_ENDPOINT_URL       = var.bucket_endpoint_url
    E2E_BUCKET_ACCESS_KEY_ID      = var.access_key_id
    E2E_BUCKET_SECRET_ACCESS_KEY  = var.secret_access_key
    E2E_MINIO_ALIAS               = var.minio_alias
    E2E_REGION                    = var.region
    E2E_POSTGRES_USER             = var.postgres_user
    E2E_POSTGRES_PASSWORD         = var.postgres_password
    E2E_POSTGRES_DB_NAME          = var.postgres_database_name
    E2E_WORKER_TAG_INGRESS        = var.worker_tag_ingress
    E2E_WORKER_TAG_EGRESS         = var.worker_tag_egress
    E2E_WORKER_TAG_COLLOCATED     = var.worker_tag_collocated
    E2E_LDAP_ADDR                 = var.ldap_address
    E2E_LDAP_DOMAIN_DN            = var.ldap_domain_dn
    E2E_LDAP_ADMIN_DN             = var.ldap_admin_dn
    E2E_LDAP_ADMIN_PASSWORD       = var.ldap_admin_password
    E2E_LDAP_USER_NAME            = var.ldap_user_name
    E2E_LDAP_USER_PASSWORD        = var.ldap_user_password
    E2E_LDAP_GROUP_NAME           = var.ldap_group_name
    E2E_MAX_PAGE_SIZE             = var.max_page_size
    E2E_CONTROLLER_CONTAINER_NAME = var.controller_container_name
    BOUNDARY_DIR                  = abspath(var.local_boundary_src_dir)
    BOUNDARY_CLI_DIR              = abspath(var.local_boundary_dir)
    MODULE_DIR                    = abspath(path.module)
  }

  inline = var.debug_no_run ? [""] : [
    "bash ./${path.module}/test_runner.sh"
  ]
}
