# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

/*
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}
*/
variable "instance_type" {
  default = ["t3.small"]
  type    = list(string)
}

data "aws_ec2_instance_type_offerings" "infra" {
  for_each = toset(var.instance_type)
  filter {
    name   = "instance-type"
    values = [each.key]
  }

  location_type = "availability-zone"
}

locals {
  az_sets    = [for d in data.aws_ec2_instance_type_offerings.infra : toset(d.locations)]
  common_azs = length(local.az_sets) > 0 ? setintersection(local.az_sets...) : []
}

output "availability_zones" {
  value = local.common_azs
}
