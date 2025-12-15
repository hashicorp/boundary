# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

data "aws_vpc" "infra" {
  id = var.vpc_id
}

data "aws_subnets" "infra" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }

  filter {
    name   = "tag:Module"
    values = [var.vpc_tag_module]
  }
}

data "aws_kms_key" "kms_key" {
  key_id = var.kms_key_arn
}
