# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "prefix" {
  type        = string
  description = "Prefix used to name various infrastructure components. Alphanumeric characters only."
  default     = "enos"
}

variable "vpc_id" {
  type        = string
  description = "Id of VPC to add additional infra resources to."
}

variable "aws_key_pair_name" {
  type        = string
  description = "key_name for the aws_key_pair resource"
  default     = "RDPKey"
}

variable "server_version" {
  type        = string
  description = "Server version for the windows instance"
  # Note that only 2025 and 2022 are supported in aws
  default = "2025"
}

variable "rdp_target_instance_type" {
  type        = string
  description = "The AWS instance type to use for servers."
  default     = "m7i-flex.xlarge"
}

variable "root_block_device_size" {
  type        = string
  description = "The volume size of the root block device."
  default     = 128
}

variable "active_directory_domain" {
  type        = string
  description = "The name of the Active Directory domain to be created on the Windows Domain Controller."
  default     = "mydomain.local"
}

variable "active_directory_netbios_name" {
  type        = string
  description = "Ostensibly the short-hand for the name of the domain."
  default     = "mydomain"
}