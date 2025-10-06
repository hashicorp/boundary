# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "project_name" {
  description = "Name of the project."
  type        = string
}

variable "environment" {
  description = "Name of the environment. (CI/Dev/Test/etc)"
  type        = string
}

variable "common_tags" {
  description = "Tags to set for all resources"
  type        = map(string)
}

variable "worker_count" {
  description = "Number of Boundary worker instances in each subnet"
  type        = number
  default     = 3
}

variable "worker_instance_type" {
  description = "EC2 Instance type"
  type        = string
  default     = "t2.small"
}

variable "worker_type_tags" {
  description = "Tag to set on worker for use in worker filters"
  type        = list(string)
  default     = ["collocated", "prod", "webservers", "linux"]
}

variable "worker_ebs_iops" {
  description = "EBS IOPS for the root volume"
  type        = number
  default     = null
}

variable "worker_ebs_size" {
  description = "EBS volume size"
  type        = number
  default     = 8
}

variable "worker_ebs_type" {
  description = "EBS volume type"
  type        = string
  default     = "gp2"
}

variable "worker_ebs_throughput" {
  description = "EBS data throughput (MiB/s) (only for gp2)"
  default     = null
}

variable "worker_monitoring" {
  description = "Enable detailed monitoring for workers"
  type        = bool
  default     = false
}

variable "controller_count" {
  description = "Number of Boundary controller instances in each subnet"
  type        = number
  default     = 3
}

variable "controller_instance_type" {
  description = "EC2 Instance type"
  type        = string
  default     = "t2.small"
}

variable "controller_ebs_iops" {
  description = "EBS IOPS for the root volume"
  type        = number
  default     = null
}

variable "controller_ebs_size" {
  description = "EBS volume size"
  type        = number
  default     = 8
}

variable "controller_ebs_type" {
  description = "EBS volume type"
  type        = string
  default     = "gp2"
}

variable "controller_ebs_throughput" {
  description = "EBS data throughput (MiB/s) (only for gp2)"
  default     = null
}

variable "controller_monitoring" {
  description = "Enable detailed monitoring for controllers"
  type        = bool
  default     = false
}

variable "ssh_user" {
  description = "SSH user to authenticate as"
  type        = string
  default     = "ubuntu"
}

variable "ssh_aws_keypair" {
  description = "SSH keypair used to connect to EC2 instances"
  type        = string
}

variable "ubuntu_ami_id" {
  description = "Ubuntu LTS AMI from enos-infra"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID from enos-infra"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of KMS Key from enos-infra"
  type        = string
}

variable "db_class" {
  description = "AWS RDS DB instance class (size/type)"
  type        = string
  default     = "db.t4g.small"
}

variable "db_engine" {
  description = "AWS RDS DB engine type"
  type        = string
  default     = "postgres"
}

variable "db_storage" {
  description = "AWS RDS DB storage volume (in GB)"
  type        = number
  default     = 10
}

variable "db_storage_type" {
  description = "AWS RDS DB storage type"
  type        = string
  default     = "gp2"
}

variable "db_storage_iops" {
  description = "AWS RDS DB storage IOPS (optional)"
  type        = string
  default     = null
}

variable "db_name" {
  description = "Name of the RDS Database"
  type        = string
  default     = null // default value defined in the locals
}

variable "db_create" {
  description = "Enables module to create RDS resources"
  type        = bool
  default     = true
}

variable "db_host" {
  description = "Address of a pre-configured PostgreSQL host"
  type        = string
  default     = null
}

variable "db_port" {
  description = "Address of a pre-configured PostgreSQL host"
  type        = number
  default     = 5432
}

variable "db_user" {
  description = "Default username for RDS database"
  type        = string
  default     = "boundary"
}

variable "db_pass" {
  description = "Default password for RDS database"
  type        = string
  default     = ""
}

variable "db_monitoring_interval" {
  description = "Interval (in seconds) to report enhanced DB metrics. Disabled by default"
  type        = number
  default     = 0
}

variable "db_monitoring_role_arn" {
  description = "The ARN of the IAM role to be used to report enhanced DB metrics. Must be set if db_monitoring_interval is set"
  type        = string
  default     = ""
}

variable "db_max_open_connections" {
  description = "The maximum number of open connections to the database. Limiting this limits the load a controller can handle."
  type        = number
  default     = 5

  validation {
    condition     = var.db_max_open_connections >= 5
    error_message = "Max open connections must be at least 5."
  }
}

variable "db_snapshot_identifier" {
  description = "The name of the DB snapshot to restore into the created RDS instance. Will be applied to all clusters created. If not set, no DB restore will be made."
  type        = string
  default     = null
}

variable "boundary_release" {
  description = "boundary release version and edition to install from releases.hashicorp.com"
  type = object({
    version = string
  })
  default = null
}

variable "boundary_artifactory_release" {
  description = "Boundary release version and edition to install from artifactory.hashicorp.engineering"
  type = object({
    username = string
    token    = string
    url      = string
    sha256   = string
  })
  default = null
}

variable "boundary_install_dir" {
  description = "The remote directory where the boundary binary will be installed"
  type        = string
  default     = "/opt/boundary/bin"
}

variable "boundary_binary_name" {
  description = "Boundary binary name"
  type        = string
  default     = "boundary"
}

variable "boundary_data_dir" {
  description = "The directory where the boundary will store data"
  type        = string
  default     = "/opt/boundary/data"
}

variable "boundary_log_dir" {
  description = "The directory where the boundary will write log output"
  type        = string
  default     = "/var/log/boundary.d"
}

variable "boundary_config_dir" {
  description = "The directory where boundary config files will live"
  type        = string
  default     = "/etc/boundary"
}

variable "local_artifact_path" {
  description = "path to a local boundary.zip"
  type        = string
  default     = null
}

variable "alb_listener_api_port" {
  description = "The load balancer port that will expose controller APIs"
  type        = number
  default     = 9200
}

variable "listener_api_port" {
  description = "The port controller instances will bind the controller API to"
  type        = number
  default     = 9200
}

variable "listener_cluster_port" {
  description = "The port controller and worker instances will bind to for communication"
  type        = number
  default     = 9201
}

variable "listener_proxy_port" {
  description = "The port worker instances will bind the worker API to"
  type        = number
  default     = 9202
}

variable "listener_ops_port" {
  description = "The port controller instances will bind the operational API to"
  type        = number
  default     = 9203
}

variable "healthcheck_path" {
  type        = string
  description = "Path to use for ALB healthcheck"
  default     = "/health"
}

variable "max_page_size" {
  description = "Max allowed page size for pagination requests"
  type        = number
  default     = 10
}

variable "alb_sg_additional_ips" {
  description = "Additional IPs to be allowed (ingress) on an ALB Security Group"
  type        = list(string)
  default     = []
}

variable "alb_sg_additional_ipv6_ips" {
  description = "Additional ipv6 IPs to be allowed (ingress) on an ALB Security Group"
  type        = list(string)
  default     = []
}

variable "boundary_license" {
  description = "Boundary license (not needed for OSS, required for enterprise)"
  type        = string
  sensitive   = true
  default     = null
}

variable "controller_config_file_path" {
  description = "Path to config file to use (relative to module directory)"
  type        = string
  default     = "templates/controller.hcl"
}

variable "worker_config_file_path" {
  description = "Path to config file to use (relative to module directory)"
  type        = string
  default     = "templates/worker.hcl"
}

variable "aws_region" {
  description = "AWS Region to create resources in"
  type        = string
  default     = "us-east-1"
}

variable "vpc_tag_module" {
  description = "Name of the Module Tag tied to the VPC"
  type        = string
  default     = "aws_vpc"
}

variable "recording_storage_path" {
  description = "Path on instance to store recordings"
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
