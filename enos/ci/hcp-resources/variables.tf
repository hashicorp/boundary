# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "us-east-1"
}

variable "hcp_boundary_cluster_id" {
  description = "The ID of the HCP Boundary cluster. If on HCP int, prepend the cluster ID with 'int-'. If on HCP dev, prepend the cluster ID with 'dev-'."
  type        = string
}

variable "boundary_zip_path" {
  description = "Path to Boundary zip file. Version should be a linux_amd64 enterprise variant."
  type        = string
}

variable "boundary_license_path" {
  description = "Path to the Boundary license file"
  type        = string
}

variable "enos_user" {
  description = "Name of user and used to tage AWS resources."
  type        = string
}

variable "aws_ssh_keypair_name" {
  description = "Name of the AWS EC2 keypair to use for SSH access"
  type        = string
}

variable "aws_ssh_private_key_path" {
  description = "Path to the private key file for the AWS EC2 keypair"
  type        = string
}

variable "worker_count" {
  description = "Number of workers to create"
  type        = number
  default     = 1
}

variable "target_count" {
  description = "Number of targets to create"
  type        = number
  default     = 1
}
