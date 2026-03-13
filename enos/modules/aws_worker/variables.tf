# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

variable "vpc_id" {
  description = "The id of the existing VPC to be used for this module"
  type        = string
}

variable "availability_zones" {
  description = "List of AWS availability zones to use (or * for all available)"
  type        = list(string)
  default     = ["*"]
}

variable "common_tags" {
  description = "Tags to set for all resources"
  type        = map(string)
  default     = { "Project" : "Enos" }
}

variable "kms_key_arn" {
  description = "ARN of KMS key used for SSHing to this module's instance"
  type        = string
}

variable "ubuntu_ami_id" {
  description = "Ubuntu LTS AMI from the VPC this module will use"
  type        = string
}

variable "worker_instance_type" {
  description = "The EC2 Instance type to be used for the worker's node"
  type        = string
  default     = "t2.small"
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

variable "worker_monitoring" {
  description = "Enable detailed monitoring for workers"
  type        = bool
  default     = false
}

variable "ebs_iops" {
  description = "EBS IOPS for the root volume"
  type        = number
  default     = null
}

variable "ebs_size" {
  description = "EBS volume size"
  type        = number
  default     = 8
}

variable "ebs_type" {
  description = "EBS volume type"
  type        = string
  default     = "gp2"
}

variable "ebs_throughput" {
  description = "EBS data throughput (MiB/s) (only for gp2)"
  default     = null
}

variable "boundary_artifactory_release" {
  description = "Boundary release, version, and edition to install from artifactory.hashicorp.engineering"
  type = object({
    username = string
    token    = string
    url      = string
    sha256   = string
  })
  default = null
}

variable "local_artifact_path" {
  description = "The path to a local boundary.zip"
  type        = string
  default     = null
}

variable "boundary_release" {
  description = "Boundary release, version, and edition to install from releases.hashicorp.com"
  type = object({
    version = string
  })
  default = null
}

variable "boundary_install_dir" {
  description = "The remote directory where the Boundary binary will be installed"
  type        = string
  default     = "/opt/boundary/bin"
}

variable "name_prefix" {
  description = "The name_prefix from the Boundary cluster module"
  type        = string
}

variable "cluster_tag" {
  description = "The cluster_tag from the Boundary cluster module"
  type        = string
}

variable "worker_type_tags" {
  description = "A list of tags to add in the worker's configuration file"
  type        = list(string)
  default     = ["prod", "webservers"]
}

variable "controller_addresses" {
  description = "A list of addresses that will be used as initial_upstreams in the worker's configuration"
  type        = list(string)
}

variable "controller_sg_id" {
  description = "The controllers' security group ID for adding rules allowing this worker to communicate with them"
  type        = string
}

variable "config_file_path" {
  description = "Path to a config file (relative to module directory)"
  type        = string
  default     = "templates/worker.hcl"
}

variable "recording_storage_path" {
  description = "Path on instance to store recordings"
  type        = string
  default     = ""
}

variable "bucket_arn" {
  description = "ARN of the S3 bucket to store recordings"
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  description = "cidr subnet of the vpc created for the enos scenario"
  type        = string
  nullable    = true
  default     = null
}

variable "vpc_cidr_ipv6" {
  description = "ipv6 cidr subnet of the vpc created for the enos scenario"
  type        = string
  nullable    = true
  default     = null
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

variable "vault_address" {
  description = "network address to a vault instance"
  type        = string
  default     = "localhost"
}

variable "vault_transit_token" {
  description = "vault token used for kms transit in the boundary config"
  type        = string
  default     = ""
}
