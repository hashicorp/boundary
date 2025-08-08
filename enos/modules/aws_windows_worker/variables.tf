# Copyright (c) HashiCorp, Inc.
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
  description = "Windows version for server"
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

# =================================================================
# aws configuration variables
# =================================================================

variable "kms_key_arn" {
  description = "ARN of KMS Key from enos-infra"
  type        = string
}

variable "aws_region" {
  description = "AWS Region to create resources in"
  type        = string
  default     = "us-east-1"
}

variable "controller_ip" {
  description = "IP address of the controller instance"
  type        = string
  default     = ""
}

variable "iam_name" {
  description = "Name of IAM role to assign to worker"
  type        = string
  default     = ""
}

variable "security_group" {
  description = "Name of security group to assign to worker"
  type        = string
  default     = ""
}

# =================================================================
# Paths for source code
# =================================================================
variable "boundary_cli_zip_path" {
  description = "Path to the boundary cli zip file (windows, amd64)"
  type        = string
  default     = ""
}

variable "boundary_ui_src_path" {
  description = "Path to the boundary UI source code"
  type        = string
  default     = ""
}

variable "boundary_src_path" {
  description = "Path to the boundary source code"
  type        = string
  default     = ""
}

# =================================================================
# Variables for the windows domain
# =================================================================

variable "active_directory_domain" {
  type        = string
  description = "The name of the Active Directory domain to be created on the Windows Domain Controller."
  default     = "mydomain.com"
}

variable "active_directory_netbios_name" {
  type        = string
  description = "Ostensibly the short-hand for the name of the domain."
  default     = "mydomain"
}

variable "domain_controller_ip" {
  type        = string
  description = "IP of the domain controller"
  default     = ""
}

variable "domain_admin_password" {
  type        = string
  description = "Domain admin password for setting up this instance in the domain"
  default     = ""
}