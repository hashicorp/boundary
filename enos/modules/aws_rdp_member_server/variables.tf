# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

variable "vpc_id" {
  type        = string
  description = "Id of VPC to add additional infra resources to."
}

# =================================================================
# ec2 instance configuration
# =================================================================
variable "server_version" {
  type        = string
  description = "Server version for the windows instance"
  default     = "2025"
}

variable "instance_type" {
  type        = string
  description = "The AWS instance type to use for servers."
  default     = "m7i-flex.xlarge"
}

variable "root_block_device_size" {
  type        = string
  description = "The volume size of the root block device."
  default     = 128
}

variable "prefix" {
  type        = string
  description = "Prefix used to name various infrastructure components. Alphanumeric characters only."
  default     = "enos"
}

variable "domain_hostname" {
  type        = string
  description = "Hostname to assign to the member server"
  default     = "MyWindowsServer"
}

variable "active_directory_domain" {
  type        = string
  description = "The name of the Active Directory domain to be created on the Windows Domain Controller."
}

variable "ip_version" {
  type        = string
  description = "IP version to use for security group rules. Valid values are '4', '6', or 'dual'."
  default     = "4"
}

# =================================================================
# domain controller information
# =================================================================
variable "domain_controller_aws_keypair_name" {
  type        = string
  description = "The AWS keypair created during creation of the domain controller."
}

variable "domain_controller_ip" {
  type        = string
  description = "IP Address of an already created Domain Controller and DNS server."
}

variable "domain_admin_password" {
  type        = string
  description = "The domain administrator password."
}

variable "domain_controller_private_key" {
  type        = string
  description = "The file path of the private key generated during creation of the domain controller."
}

variable "domain_controller_sec_group_id_list" {
  type        = list(any)
  description = "ID's of AWS Network Security Groups created during creation of the domain controller."
}

variable "kerberos_only" {
  type        = bool
  description = "Only allow kerberos auth"
  default     = false
}
