terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    enos = {
      source  = "hashicorp.com/qti/enos"
      version = ">= 0.1.22"
    }
  }
}

variable "instance_type" {
  default = ["t3.small"]
  type    = list(string)
}

data "aws_ec2_instance_type_offerings" "infra" {
  filter {
    name   = "instance-type"
    values = var.instance_type
  }

  location_type = "availability-zone"
}

output "availability_zones" {
  value = data.aws_ec2_instance_type_offerings.infra.locations
}

