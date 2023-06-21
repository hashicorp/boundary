# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Infrastructure
variable "aws_ssh_keypair_name" {
  description = "Name of the AWS keypair Enos will use to connect"
  type        = string
}

variable "aws_ssh_private_key_path" {
  description = "Path to the SSH key Enos will use to connect"
  type        = string
}

# Tagging
variable "environment" {
  description = "A environment name to use for resource tagging"
  type        = string
  default     = "dev"
}

variable "enos_user" {
  description = "The user running the tests, this is by default your OS user or Github User"
  type        = string
}

# Test configs
variable "boundary_docker_image_name" {
  description = "Name:Tag of Docker image to use"
  type        = string
  default     = "docker.io/hashicorp/boundary:latest"
}

variable "boundary_docker_image_file" {
  description = "Path to Boundary Docker image"
  type        = string
  default     = ""
}

variable "worker_instance_type" {
  description = "EC2 Instance type"
  type        = string
  default     = "t3a.small"
}

variable "worker_count" {
  description = "How many worker instances to create"
  type        = number
  default     = 1
}

variable "controller_instance_type" {
  description = "EC2 Instance type"
  type        = string
  default     = "t3a.small"
}

variable "controller_count" {
  description = "How many controller instances to create"
  type        = number
  default     = 1
}

variable "alb_listener_api_port" {
  description = "What port the ALB will listen on to proxy controller API requests"
  type        = string
  default     = 9200
}

variable "project_name" {
  description = "The description of the project"
  type        = string
  default     = "boundary-enos-integration"
}

variable "tags" {
  description = "Tags that will be applied to infrastructure resources that support tagging"
  type        = map(string)
  default     = null
}

variable "target_instance_type" {
  description = "Instance type for test target nodes"
  type        = string
  default     = "t2.micro"
}

variable "target_count" {
  description = "How many target instances to create"
  type        = number
  default     = 1
}

variable "local_boundary_dir" {
  description = "Path to local boundary executable"
  type        = string
}

variable "local_boundary_ui_dir" {
  description = "Path to local boundary-ui directory"
  type        = string
  default     = null
}

variable "crt_bundle_path" {
  description = "Path to CRT generated boundary bundle"
  type        = string
  default     = null
}

variable "boundary_install_dir" {
  description = "Path boundary binaries will be installed to on remote instances"
  type        = string
  default     = "/opt/boundary/bin"
}

variable "tfc_api_token" {
  description = "The Terraform Cloud QTI Organization API token."
  type        = string
}

variable "vault_instance_type" {
  description = "Instance type for test target nodes"
  type        = string
  default     = "t3a.small"
}

variable "vault_version" {
  description = "Version of Vault to use"
  type        = string
  default     = "1.12.2"
}

variable "test_email" {
  description = "Email address for setting up AWS IAM user (module: iam_setup)"
  type        = string
  default     = null
}

variable "local_build_target" {
  description = "Which make build target(s) to use for the local builder variant"
  type        = string
  default     = "build-ui build"
}

variable "e2e_debug_no_run" {
  description = "If set, this will prevent test suites from running"
  type        = bool
  default     = false
}

variable "docker_mirror" {
  description = ""
  type        = string
  default     = "docker.mirror.hashicorp.services"
}

variable "boundary_binary_name" {
  description = "Boundary binary name"
  type        = string
  default     = "boundary"
}

variable "boundary_edition" {
  description = "Edition of boundary build"
  type        = string
  default     = "oss"
}

variable "boundary_license_path" {
  description = "Boundary license path"
  type        = string
  default     = null
}

variable "go_test_timeout" {
  description = "Timeout for go test used in e2e tests"
  type        = string
  default     = "10m"
}

variable "aws_region" {
  description = "AWS region where the resources will be created"
  type        = string
}
