variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Name of the environment"
  type        = string
}

variable "common_tags" {
  description = "Tags to set for all resources"
  type        = map(string)
  default     = { "Project" : "Enos" }
}

variable "instance_type" {
  description = "EC2 Instance"
  type        = string
  default     = "t3a.small"
}

variable "instance_count" {
  description = "Number of EC2 instances in each subnet"
  type        = number
  default     = 3
}

variable "ssh_aws_keypair" {
  description = "SSH keypair used to connect to EC2 instances"
  type        = string
}

variable "enos_transport_user" {
  description = "Enos transport username. If unset the provider level configuration will be used"
  type        = string
  default     = null
}

variable "ami_id" {
  description = "AMI from enos-infra"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID from enos-infra"
  type        = string
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of KMS Key from enos-infra"
}

variable "nomad_release" {
  type = object({
    version = string
    edition = string
  })
  description = "Vault release version and edition to install from releases.hashicorp.com"
  default     = null
}

variable "nomad_artifactory_release" {
  type = object({
    username = string
    token    = string
    url      = string
    sha256   = string
  })
  description = "Vault release version and edition to install from artifactory.hashicorp.engineering"
  default     = null
}

variable "nomad_local_artifact_path" {
  type        = string
  description = "The path to a locally built Nomad artifact to install"
  default     = null
}

variable "consul_release" {
  type = object({
    version = string
    edition = string
  })
  description = "Consul release version and edition to install from releases.hashicorp.com"
  default = {
    version = "1.10.3"
    edition = "oss"
  }
}

variable "consul_install_dir" {
  type        = string
  description = "The directory where the consul binary will be installed"
  default     = "/usr/local/bin"
}

variable "nomad_install_dir" {
  type        = string
  description = "The directory where the Nomad binary will be installed"
  default     = "/usr/local/bin"
}

variable "consul_data_dir" {
  type        = string
  description = "The directory where the consul will store data"
  default     = "/opt/consul/data"
}

variable "consul_log_dir" {
  type        = string
  description = "The directory where the consul will write log output"
  default     = "/var/log/consul.d"
}

variable "dependencies_to_install" {
  type        = list(string)
  description = "A list of dependencies to install"
  default     = ["jq"]
}

variable "nomad_cluster_tag" {
  type        = string
  description = "Cluster tag for the Nomad cluster"
  default     = null
}

variable "nomad_node_prefix" {
  type        = string
  description = "The Nomad node prefix"
  default     = "node"
}

variable "private_key_path" {
  type        = string
  description = "The fully qualified path to a local private key for use with the AWS keypair"
}
