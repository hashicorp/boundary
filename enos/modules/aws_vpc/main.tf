# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

variable "name" {
  type        = string
  default     = "enos-vpc"
  description = "The name of the VPC"
}

variable "availability_zones" {
  description = "List of AWS availability zones to use (or * for all available)"
  type        = list(string)
  default     = ["*"]
}

variable "cidr" {
  type        = string
  default     = "10.13.0.0/16"
  description = "CIDR block for the VPC"
}

variable "environment" {
  description = "Name of the environment."
  type        = string
  default     = "enos-environment"
}

variable "common_tags" {
  description = "Tags to set for all resources"
  type        = map(string)
  default     = { "Project" : "enos" }
}

variable "create_kms_key" {
  description = "Whether or not to create an key management service key"
  type        = bool
  default     = true
}

variable "ami_architectures" {
  type        = list(string)
  description = "The AMI architectures to fetch AMI IDs for."
  default     = ["amd64", "arm64"]
}

locals {
  // AWS AMIs standardized on the x86_64 label for 64bit x86 architectures, therefore amd64 should be rather x86_64.
  architecture_filters = [for arch in var.ami_architectures : (arch == "amd64" ? "x86_64" : arch)]
  tag_module           = "aws_vpc"
  common_tags = merge(
    var.common_tags,
    {
      "Module" = local.tag_module
    },
  )
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "zone-name"
    values = var.availability_zones
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  count       = length(local.architecture_filters)

  filter {
    name   = "name"
    values = ["hc-base-ubuntu-2204-*"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = [local.architecture_filters[count.index]]
  }

  owners = ["888995627335"] # ami-prod account
}

# !! update RHEL
data "aws_ami" "rhel" {
  most_recent = true
  count       = length(local.architecture_filters)

  filter {
    name   = "name"
    values = ["RHEL-8.8*HVM-20*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = [local.architecture_filters[count.index]]
  }

  owners = ["309956199498"] # Redhat
}

resource "random_string" "cluster_id" {
  length  = 8
  lower   = true
  upper   = false
  numeric = false
  special = false
}

resource "aws_kms_key" "key" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "enos-kms-key"
  deletion_window_in_days = 7 // 7 is the shortest allowed window
}

resource "aws_kms_alias" "alias" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/enos_key-${random_string.cluster_id.result}"
  target_key_id = aws_kms_key.key[0].key_id
}

resource "aws_vpc" "vpc" {
  cidr_block           = var.cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.name}-${split(":", data.aws_caller_identity.current.user_id)[1]}"
    },
  )
}

resource "aws_subnet" "subnet" {
  count                   = length(data.aws_availability_zones.available.names)
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(var.cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.name}-subnet-${data.aws_availability_zones.available.names[count.index]}"
    },
  )
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.name}-igw"
    },
  )
}

resource "aws_route" "igw" {
  route_table_id         = aws_vpc.vpc.default_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_security_group" "default" {
  vpc_id = aws_vpc.vpc.id

  ingress {
    description = "allow_ingress_from_all"
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "allow_egress_from_all"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.name}-default"
    },
  )
}

output "vpc_id" {
  description = "Created VPC ID"
  value       = aws_vpc.vpc.id
}

output "vpc_cidr" {
  description = "CIDR for whole VPC"
  value       = aws_vpc.vpc.cidr_block
}

output "vpc_subnets" {
  description = "Generated subnet IDs and CIDRs"
  value       = { for s in aws_subnet.subnet : s.id => s.cidr_block }
}

output "kms_key_arn" {
  description = "ARN of the generated KMS key"
  value       = try(aws_kms_key.key[0].arn, null)
}

output "kms_key_alias" {
  description = "Alias of the generated KMS key"
  value       = try(aws_kms_alias.alias[0].name, null)
}

output "availability_zone_names" {
  description = "All availability zones with resources"
  value       = data.aws_availability_zones.available.names
}

output "ami_ids" {
  description = "The AWS AMI IDs for to use for ubuntu and rhel based instance for the amd64 and arm64 architectures."
  value = {
    ubuntu = { for idx, arch in var.ami_architectures : arch => data.aws_ami.ubuntu[idx].id }
    rhel   = { for idx, arch in var.ami_architectures : arch => data.aws_ami.rhel[idx].id }
  }
}

output "vpc_tag_module" {
  value = local.tag_module
}
