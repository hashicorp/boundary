data "aws_vpc" "infra" {
  id = var.vpc_id
}

data "aws_subnets" "infra" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }
}

data "aws_caller_identity" "current" {}

data "aws_kms_key" "kms_key" {
  key_id = var.kms_key_arn
}
