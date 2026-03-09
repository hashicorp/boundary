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

variable "prefix" {
  type        = string
  description = "Prefix used to name various infrastructure components. Alphanumeric characters only."
  default     = "enos"
}

variable "root_block_device_size" {
  type        = string
  description = "The volume size of the root block device."
  default     = 128
}

variable "aws_key_pair_name" {
  type        = string
  description = "key_name for the aws_key_pair resource"
  default     = "RDPKey"
}

variable "ip_version" {
  type        = string
  description = "IP version to use for security group rules. Valid values are '4', '6', or 'dual'."
  default     = "4"
}

# =================================================================
# domain information
# =================================================================
variable "active_directory_domain" {
  type        = string
  description = "The name of the Active Directory domain to be created on the Windows Domain Controller."
  default     = "mydomain.com"
}
