# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "vpc_id" {
  type        = string
  description = "Id of VPC to add additional infra resources to."
}

# =================================================================
# ec2 instance configuration
# =================================================================
variable "client_version" {
  type        = string
  description = "Windows version for client, win10 and win11 supported versions"
  default     = "win10"
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

# =================================================================
# additional resources
# =================================================================
variable "boundary_cli_zip_path" {
  description = "Path to the boundary cli zip file (windows, amd64)"
  type        = string
  default     = ""
}

variable "boundary_src_path" {
  description = "Path to the boundary source code"
  type        = string
  default     = ""
}
