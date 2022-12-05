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

variable "skip_failing_bats_tests" {
  description = "Skip known Bats test failures"
  type        = string
  default     = "false"
}

variable "vault_instance_type" {
  description = "Instance type for test target nodes"
  type        = string
  default     = "t3a.small"
}

variable "test_email" {
  description = "Email address for setting up AWS IAM user (module: iam_setup)"
  type        = string
  default     = null
}
