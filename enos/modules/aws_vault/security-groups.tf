# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

resource "aws_security_group" "enos_vault_sg" {
  count       = var.deploy ? 1 : 0
  name        = "vault-sg-${random_string.cluster_id.result}"
  description = "SSH and Vault Traffic"
  vpc_id      = var.vpc_id

  # SSH
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = local.network_stack[var.ip_version].ingress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].ingress_ipv6_cidr_blocks
  }

  # Vault traffic
  ingress {
    from_port        = 8200
    to_port          = 8201
    protocol         = "tcp"
    cidr_blocks      = local.network_stack[var.ip_version].ingress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].ingress_ipv6_cidr_blocks
  }

  # Consul Agent traffic
  ingress {
    from_port        = 8301
    to_port          = 8301
    protocol         = "tcp"
    cidr_blocks      = local.network_stack[var.ip_version].ingress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].ingress_ipv6_cidr_blocks
  }

  ingress {
    from_port        = 8301
    to_port          = 8301
    protocol         = "udp"
    cidr_blocks      = local.network_stack[var.ip_version].ingress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].ingress_ipv6_cidr_blocks
  }

  # Internal Traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    cidr_blocks = [data.aws_vpc.infra.cidr_block]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = local.network_stack[var.ip_version].egress_cidr_blocks
    ipv6_cidr_blocks = local.network_stack[var.ip_version].egress_ipv6_cidr_blocks
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_suffix}-vault-sg"
    },
  )
}
