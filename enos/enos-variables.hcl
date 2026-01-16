# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

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
  default     = null
}

variable "local_boundary_src_dir" {
  description = "Path to local boundary source code directory"
  type        = string
  default     = null
}

variable "local_boundary_ui_src_dir" {
  description = "Path to local boundary-ui source code directory"
  type        = string
  default     = null
}

variable "crt_bundle_path" {
  description = "Path to CRT generated boundary bundle"
  type        = string
  default     = null
}

variable crt_bundle_path_windows {
  description = "Path to CRT generated boundary bundle for windows"
  type        = string
  default     = null
}

variable "boundary_install_dir" {
  description = "Path boundary binaries will be installed to on remote instances"
  type        = string
  default     = "/opt/boundary/bin"
}

variable "vault_instance_type" {
  description = "Instance type for test target nodes"
  type        = string
  default     = "t3a.small"
}

variable "vault_version" {
  description = "Version of Vault to use"
  type        = string
  default     = "1.17.6"
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
  description = "URL to the docker repository"
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

variable "boundary_license" {
  description = "Boundary license"
  type        = string
  default     = null
}

variable "vault_license_path" {
  description = "Vault license path"
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
  default     = "us-east-1"
}

variable "go_version" {
  description = "Version of Golang used by the application under test"
  type        = string
  default     = ""
}

variable "hcp_boundary_cluster_id" {
  description = "ID of the Boundary cluster in HCP"
  type        = string
  default     = ""
  // If using HCP int, ensure that the cluster id starts with "int-"
  // Example: "int-19283a-123123-..."
}

variable "gcp_target_instance_type" {
  description = "Instance type for test target nodes"
  type        = string
  default     = "e2-micro"
}

variable "gcp_region" {
  description = "GCP region where the resources will be created"
  type        = string
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "GCP zone where the resources will be created"
  type        = string
  default     = "us-central1-a"
}

variable "gcp_project_id" {
  description = "GCP project where the resources will be created"
  type        = string
  sensitive   = true
  default     = ""
}

variable "gcp_private_key_path" {
  description = "Path to the GCP private key"
  type        = string
  sensitive   = true
  default     = null
}

variable "gcp_private_key" {
  description = "GCP private key"
  type        = string
  sensitive   = true
  default     = null
}

variable "gcp_private_key_id" {
  description = "GCP private key ID"
  type        = string
  sensitive   = true
  default     = null
}

variable "gcp_client_email" {
  description = "GCP client email"
  type        = string
  sensitive   = true
  default     = null
}

variable "windows_instance_type" {
  description = "Instance type for Windows client nodes"
  type        = string
  default     = "m7i-flex.xlarge"
}

variable "ui_build_override" {
  description = "Override for build for UI automation"
  type        = string
  default     = ""
}

variable "github_token" {
  description = "github token to the hashicorp org. needed to run RDP automated tests (requires contents (read-only) and actions (read-only) with fine-grained tokens or repo access using classic tokens)"
  type        = string
  default     = ""
}

variable "worker_version" {
  description = "Manually set worker version to test different worker/controller version combinations"
  type        = string
  default     = null
}