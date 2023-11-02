# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

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

output "target_ips" {
  value = aws_instance.target.*.private_ip
}
