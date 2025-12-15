# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

data "enos_environment" "localhost" {}

locals {
  listener_ports = {
    "api" : var.listener_api_port,
    "cluster" : var.listener_cluster_port,
    "proxy_port" : var.listener_proxy_port,
    "ops" : var.listener_ops_port,
  }
  alb_listener_ports = {
    "api" : var.alb_listener_api_port,
  }
}

resource "aws_security_group" "boundary_sg" {
  name        = "boundary-sg-${random_string.cluster_id.result}"
  description = "SSH and boundary Traffic"
  vpc_id      = var.vpc_id

  # SSH
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = local.network_stack[var.ip_version].ingress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].ingress_ipv6_cidr_blocks
  }

  dynamic "ingress" {
    for_each = local.listener_ports

    content {
      cidr_blocks      = local.network_stack[var.ip_version].ingress_cidr_blocks
      ipv6_cidr_blocks = local.network_stack[var.ip_version].ingress_ipv6_cidr_blocks
      description      = ingress.key
      from_port        = ingress.value
      to_port          = ingress.value
      prefix_list_ids  = []
      protocol         = "tcp"
      self             = null
      security_groups  = []
    }
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = local.network_stack[var.ip_version].egress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].egress_ipv6_cidr_blocks
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-boundary-sg"
    },
  )
}

# Other modules use this SG to add rules for the Boundary controllers
resource "aws_security_group" "boundary_aux_sg" {
  name        = "boundary-sg-aux-${random_string.cluster_id.result}"
  description = "Extra controller rules"
  vpc_id      = var.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-boundary-aux-sg"
    },
  )
}

resource "aws_security_group" "boundary_alb_sg" {
  name        = "boundary-alb-sg-${random_string.cluster_id.result}"
  description = "boundary Traffic"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = local.alb_listener_ports

    content {
      cidr_blocks = flatten([
        try(format("%s/32", aws_instance.controller.0.public_ip), []),
        local.network_stack[var.ip_version].ingress_cidr_blocks]
      )
      ipv6_cidr_blocks = flatten([
        try(cidrsubnet("${aws_instance.controller.0.ipv6_addresses[0]}/64", 0, 0), []),
        local.network_stack[var.ip_version].ingress_ipv6_cidr_blocks]
      )
      description     = ingress.key
      from_port       = ingress.value
      to_port         = ingress.value
      prefix_list_ids = []
      protocol        = "tcp"
      self            = null
      security_groups = []
    }
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = local.network_stack[var.ip_version].egress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].egress_ipv6_cidr_blocks
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-boundary-alb-sg"
    },
  )
}


resource "aws_security_group" "boundary_db_sg" {
  name        = "boundary-db-sg-${random_string.cluster_id.result}"
  description = "Postgres Traffic"
  vpc_id      = var.vpc_id

  ingress {
    cidr_blocks      = local.network_stack[var.ip_version].ingress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].ingress_ipv6_cidr_blocks
    description      = "database"
    from_port        = 5432
    to_port          = 5432
    prefix_list_ids  = []
    protocol         = "tcp"
    self             = null
    security_groups  = []
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = local.network_stack[var.ip_version].egress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].egress_ipv6_cidr_blocks
  }

  tags = merge(local.common_tags,
    {
      Name = "${local.name_prefix}-boundary-db-sg"
    },
  )
}
