# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

variable "ami_id" {
  description = "AMI from enos-infra"
  type        = string
}

variable "common_tags" {
  description = "Tags to set for all resources"
  type        = map(string)
  default     = { "Project" : "Enos" }
}

variable "consul_cluster_tag" {
  type        = string
  description = "cluster tag for consul cluster"
  default     = null
}

variable "consul_data_dir" {
  type        = string
  description = "The directory where the consul will store data"
  default     = "/opt/consul/data"
}

variable "consul_install_dir" {
  type        = string
  description = "The directory where the consul binary will be installed"
  default     = "/opt/consul/bin"
}

variable "consul_license" {
  type        = string
  description = "The license to use for Consul Enterprise"
  default     = null
}

variable "consul_log_dir" {
  type        = string
  description = "The directory where the consul will write log output"
  default     = "/var/log/consul.d"
}

variable "consul_log_level" {
  type        = string
  description = "The consul service log level"
  default     = "INFO"
}

variable "consul_release" {
  type = object({
    version = string
    edition = string
  })
  description = "Consul release version and edition to install from releases.hashicorp.com"
  default = {
    version = "1.15.3"
    edition = "oss"
  }
}

variable "dependencies_to_install" {
  type        = list(string)
  description = "A list of dependencies to install"
  default     = []
}

variable "environment" {
  description = "Name of the environment."
  type        = string
}

variable "deploy" {
  description = "Flag to toggle whether or not all the resources defined in this module should be deployed."
  type        = bool
  default     = false
}

variable "instance_count" {
  description = "Number of EC2 instances in each subnet"
  type        = number
  default     = 3
}

variable "instance_type" {
  description = "EC2 Instance"
  type        = string
  default     = "t2.micro"
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of KMS Key from enos-infra"
  default     = null
}

variable "manage_service" {
  type        = bool
  description = "Manage the service users and systemd"
  default     = true
}

variable "project_name" {
  description = "Name of the project."
  type        = string
}

variable "sg_additional_ips" {
  description = "A list of additional IPv4 IPs to allow by Vault security groups (use with caution)"
  type        = list(string)
  default     = []
}

variable "sg_additional_ipv6_ips" {
  description = "A list of additional IPv6 IPs to allow by Vault security groups (use with caution)"
  type        = list(string)
  default     = []
}

variable "aws_ssh_keypair_name" {
  description = "SSH keypair used to connect to EC2 instances"
  type        = string
}

variable "aws_ssh_private_key" {
  description = "SSH private key content for connecting to instances"
  type        = string
  sensitive   = true
}

variable "storage_backend" {
  type        = string
  description = "The type of Vault storage backend which will be used"
  default     = "raft"

  validation {
    condition     = contains(["raft", "consul"], var.storage_backend)
    error_message = "The \"storage_backend\" must be one of: [raft|consul]."
  }
}

variable "storage_backend_addl_config" {
  type        = map(any)
  description = "A set of key value pairs to inject into the storage block"
  default     = {}
}

variable "unseal_method" {
  type        = string
  description = "The method by which to unseal the Vault cluster"
  default     = "awskms"

  validation {
    condition     = contains(["awskms", "shamir"], var.unseal_method)
    error_message = "The unseal_method must be one of 'awskms or 'shamir'."
  }
}

variable "vault_artifactory_release" {
  type = object({
    username = string
    token    = string
    url      = string
    sha256   = string
  })
  description = "Vault release version and edition to install from artifactory.hashicorp.engineering"
  default     = null
}

variable "vault_cluster_tag" {
  type        = string
  description = "Cluster tag for Vault cluster"
  default     = null
}

variable "vault_config_dir" {
  type        = string
  description = "The directory to use for Vault configuration"
  default     = "/etc/vault.d"
}

variable "vault_init" {
  type        = bool
  description = "Initialize the Vault cluster"
  default     = true
}

variable "vault_install_dir" {
  type        = string
  description = "The directory where the vault binary will be installed"
  default     = "/opt/vault/bin"
}

variable "vault_license" {
  type        = string
  sensitive   = true
  description = "vault license"
  default     = null
}

variable "vault_local_artifact_path" {
  type        = string
  description = "The path to a locally built vault artifact to install"
  default     = null
}

variable "vault_log_dir" {
  type        = string
  description = "The directory to use for Vault logs"
  default     = "/var/log/vault.d"
}

variable "vault_log_level" {
  type        = string
  description = "The vault service log level"
  default     = "info"

  validation {
    condition     = contains(["trace", "debug", "info", "warn", "error"], var.vault_log_level)
    error_message = "The vault_log_level must be one of 'trace', 'debug', 'info', 'warn', or 'error'."
  }
}

variable "vault_node_prefix" {
  type        = string
  description = "The vault node prefix"
  default     = "node"
}

variable "vault_release" {
  type = object({
    version = string
    edition = string
  })
  description = "Vault release version and edition to install from releases.hashicorp.com"
  default     = null
}

variable "vault_root_token" {
  type        = string
  description = "Vault root token"
  default     = null
}

variable "vault_unseal_when_no_init" {
  type        = bool
  description = "Unseal the Vault manually even if we're not initializing it"
  default     = false
}

variable "vault_unseal_keys" {
  type        = list(string)
  description = "Vault unseal keys to use for shamir unseal, usually only for already initialized clusters"
  default     = null
}

variable "vpc_id" {
  description = "VPC ID from enos-infra"
  type        = string
}

variable "vault_environment" {
  description = "Optional environment variables to set when running the vault service"
  type        = map(string)
  default     = null
}

variable "enable_file_audit_device" {
  description = "If true the file audit device will be enabled at the path /var/log/vault/vault_audit.log"
  type        = bool
  default     = true
}

variable "ip_version" {
  type        = string
  description = "Optional variable that configures the vault instance to run on a ipv4, ipv6, or dualstack network"
  default     = "4"

  validation {
    condition     = contains(["4", "6", "dual"], var.ip_version)
    error_message = "Valid values for ip_version are (4, 6, dual)."
  }
}
