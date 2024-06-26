# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "aws_security_group" "enos_vault_sg" {
  name        = "vault-sg-${random_string.cluster_id.result}"
  description = "SSH and Vault Traffic"
  vpc_id      = var.vpc_id

  # SSH
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
  }

  # Vault traffic
  ingress {
    from_port = 8200
    to_port   = 8201
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
      formatlist("%s/32", var.sg_additional_ips),
    ])
  }

  # Consul Agent traffic
  ingress {
    from_port = 8301
    to_port   = 8301
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
  }

  ingress {
    from_port = 8301
    to_port   = 8301
    protocol  = "udp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.localhost.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
  }

  # Internal Traffic
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_suffix}-vault-sg"
    },
  )
}
