# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "app.terraform.io/hashicorp-qti/enos"
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

data "enos_environment" "current" {}

resource "aws_security_group" "boundary_target" {
  name_prefix = "boundary-target-sg"
  description = "SSH and boundary Traffic"
  vpc_id      = var.vpc_id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidr
  }

  ingress {
    description = "SSH to the instance"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = flatten([formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses)])
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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

  tags = merge(var.additional_tags, {
    "Name" : "boundary-target-${count.index}",
    "Type" : "target",
    "Project" : "Enos",
    "Project Name" : "qti-enos-boundary",
    "Environment" : var.environment
    "Enos User" : var.enos_user,
  })
}

resource "enos_remote_exec" "wait" {
  for_each = {
    for idx, instance in aws_instance.target : idx => instance
  }

  inline = ["cloud-init status --wait"]

  transport = {
    ssh = {
      host = aws_instance.target[each.key].public_ip
    }
  }
}

output "target_ips" {
  value = aws_instance.target.*.private_ip
}
