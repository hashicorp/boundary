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

variable "ip_version" {
  type        = string
  description = "IP version to use for security group rules. Valid values are '4', '6', or 'dual'."
  default     = "4"
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
  type        = list(string)
  default     = []
}

variable "iam_name" {
  description = "Name of IAM role to assign to worker"
  type        = string
  default     = ""
}

variable "boundary_security_group" {
  description = "Name of security group with boundary related ports"
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

# =================================================================
# Variables for the windows domain
# =================================================================
variable "domain_controller_aws_keypair_name" {
  type        = string
  description = "The AWS keypair created during creation of the domain controller."
}

variable "active_directory_domain" {
  type        = string
  description = "The name of the Active Directory domain to be created on the Windows Domain Controller."
  default     = "mydomain.com"
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

variable "domain_controller_private_key" {
  type        = string
  description = "The file path of the private key generated during creation of the domain controller."
}

variable "domain_controller_sec_group_id_list" {
  type        = list(any)
  description = "ID's of AWS Network Security Groups created during creation of the domain controller."
}

# =================================================================
# Boundary Worker Configuration
# =================================================================
variable "worker_config_file_path" {
  description = "Path to config file to use (relative to module directory)"
  type        = string
  default     = "scripts/worker.hcl"
}

variable "hcp_boundary_cluster_id" {
  description = "ID of the Boundary cluster in HCP"
  type        = string
  default     = ""
  // If using HCP int, ensure that the cluster id starts with "int-"
  // Example: "int-19283a-123123-..."
}
