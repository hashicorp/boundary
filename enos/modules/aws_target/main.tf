# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "vpc_id" {}
variable "ami_id" {}
variable "subnet_ids" {}
variable "target_count" {}
variable "environment" {}
variable "project_name" {}
variable "instance_type" {}
variable "aws_ssh_keypair_name" {}
variable "enos_user" {}
variable "additional_tags" {
  default = {}
}
variable "ingress_cidr" {
  type    = list(string)
  default = ["10.0.0.0/8"]
}

variable "ingress_ipv6_cidr" {
  type    = list(string)
  default = []
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

data "enos_environment" "current" {}

data "aws_caller_identity" "current" {}
locals {
  network_stack = {
    "4" = {
      ingress_cidr_blocks = flatten([
        formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
        var.ingress_cidr,
      ])
      ingress_ipv6_cidr_blocks = [],
      egress_cidr_blocks       = ["0.0.0.0/0"],
      egress_ipv6_cidr_blocks  = [],
      ipv6_address_count       = 0,
    },
    "6" = {
      ingress_cidr_blocks = [],
      ingress_ipv6_cidr_blocks = flatten([
        [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
        var.ingress_ipv6_cidr,
      ])
      egress_cidr_blocks      = [],
      egress_ipv6_cidr_blocks = ["::/0"],
      ipv6_address_count      = 1,
    },
    "dual" = {
      ingress_cidr_blocks = flatten([
        # allow ingress from ipv4 to allow for test setup from ci
        formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
        var.ingress_cidr,
      ])
      ingress_ipv6_cidr_blocks = flatten([
        [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
        var.ingress_ipv6_cidr,
      ])
      egress_cidr_blocks      = [],
      egress_ipv6_cidr_blocks = ["::/0"],
      ipv6_address_count      = 1,
    }
  }
}

resource "aws_security_group" "boundary_target" {
  name_prefix = "boundary-target-sg"
  description = "SSH and boundary Traffic"
  vpc_id      = var.vpc_id

  ingress {
    description      = "SSH to the instance"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = local.network_stack[var.ip_version].ingress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].ingress_ipv6_cidr_blocks
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = local.network_stack[var.ip_version].egress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].egress_ipv6_cidr_blocks
  }

  tags = {
    "Name" : "boundary-target-sg"
  }
}

resource "aws_instance" "target" {
  count                  = var.target_count
  ami                    = var.ami_id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.boundary_target.id]
  subnet_id              = var.subnet_ids[count.index % length(var.subnet_ids)]
  key_name               = var.aws_ssh_keypair_name

  ipv6_address_count = local.network_stack[var.ip_version].ipv6_address_count

  tags = merge(var.additional_tags, {
    "Name" : "boundary-target-${count.index}-${split(":", data.aws_caller_identity.current.user_id)[1]}",
    "Type" : "target",
    "Project" : "Enos",
    "Project Name" : "qti-enos-boundary",
    "Environment" : var.environment,
    "Enos User" : var.enos_user,
  })

  root_block_device {
    encrypted = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

resource "enos_remote_exec" "wait" {
  for_each = {
    for idx, instance in aws_instance.target : idx => instance
  }

  inline = ["cloud-init status --wait"]

  transport = {
    ssh = {
      host = var.ip_version == "6" ? aws_instance.target[each.key].ipv6_addresses[0] : aws_instance.target[each.key].public_ip
    }
  }
}

output "target_private_ips" {
  value = var.ip_version == "4" ? aws_instance.target.*.private_ip : flatten(aws_instance.target.*.ipv6_addresses)
}

output "target_public_ips" {
  value = var.ip_version == "4" ? aws_instance.target.*.public_ip : flatten(aws_instance.target.*.ipv6_addresses)
}
