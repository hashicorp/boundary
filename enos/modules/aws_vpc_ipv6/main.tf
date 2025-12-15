# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_version = ">= 1.1.2"

  required_providers {
    enos = {
      source  = "registry.terraform.io/hashicorp-forge/enos"
      version = ">= 0.3.25"
    }
  }
}

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

variable "ipv6_cidr" {
  type        = string
  default     = "fd13:1:1::/48"
  description = "IPv6 CIDR block for the VPC"
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

variable "ip_version" {
  description = "ip version used to setup boundary instance, should be 4, 6, or dual"
  type        = string
  default     = "4"

  validation {
    condition     = contains(["4", "6", "dual"], var.ip_version)
    error_message = "ip_version must be one of: [4, 6, dual]"
  }
}

data "aws_caller_identity" "current" {}

data "enos_environment" "localhost" {}

check "ipv6_connection" {
  assert {
    condition     = var.ip_version != "6" || data.enos_environment.localhost.public_ipv6_addresses != null
    error_message = "no ipv6 connectivity detected, unable to set up ipv6-only tests"
  }
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

  # Currently latest LTS-1
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-*-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = [local.architecture_filters[count.index]]
  }

  owners = ["099720109477"] # Canonical
}

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
  cidr_block                       = var.cidr
  enable_dns_hostnames             = true
  enable_dns_support               = true
  assign_generated_ipv6_cidr_block = true
  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.name}-${split(":", data.aws_caller_identity.current.user_id)[1]}"
    },
  )
}

resource "aws_subnet" "subnet" {
  count                           = length(data.aws_availability_zones.available.names)
  vpc_id                          = aws_vpc.vpc.id
  cidr_block                      = cidrsubnet(var.cidr, 8, count.index)
  availability_zone               = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch         = true
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.vpc.ipv6_cidr_block, 8, count.index + 16) # + 16 so we have some guaranteed unused subnets for other workers
  assign_ipv6_address_on_creation = true

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

resource "aws_route" "igw_ipv6" {
  route_table_id              = aws_vpc.vpc.default_route_table_id
  destination_ipv6_cidr_block = "::/0"
  gateway_id                  = aws_internet_gateway.igw.id
}

resource "aws_route" "igw_ipv4" {
  count                  = var.ip_version == "6" ? 0 : 1
  route_table_id         = aws_vpc.vpc.default_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_security_group" "default" {
  vpc_id = aws_vpc.vpc.id

  ingress {
    description      = "allow_ingress_from_ipv6_only"
    from_port        = 0
    to_port          = 0
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "allow_ingress_only_from_ipv4_enos_host"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = flatten([
      # allow ingress from ipv4 to allow for test setup from ci
      # TODO: remove this when github actions has ipv6 compatibility
      formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses)
    ])
  }

  egress {
    description = "allow_egress_only_to_ipv4_enos_host"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = flatten([
      # allow egress to ipv4 to allow for test setup from ci
      # TODO: remove this when github actions has ipv6 compatibility
      formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses)
    ])
  }

  egress {
    description      = "allow_egress_from_ipv6_only"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
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

output "vpc_cidr_ipv6" {
  description = "ipv6 CIDR for whole VPC"
  value       = aws_vpc.vpc.ipv6_cidr_block
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
