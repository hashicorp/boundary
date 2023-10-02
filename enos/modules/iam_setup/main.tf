# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

data "aws_caller_identity" "current" {}

variable "test_id" {}
variable "test_email" {}

locals {
  # Use the AWS provided email if users are running this, override with variable for CI
  user_email = var.test_email == null ? split(":", data.aws_caller_identity.current.user_id)[1] : var.test_email
}

resource "aws_iam_user" "boundary" {
  name                 = "boundary-e2e-${var.test_id}"
  tags                 = { boundary-demo = local.user_email }
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/BoundaryDemoPermissionsBoundary"
}

resource "aws_iam_user_policy" "boundary" {
  name = "boundary_e2e_${var.test_id}"
  user = aws_iam_user.boundary.name
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "ec2:DescribeInstances"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_access_key" "boundary" {
  user = aws_iam_user.boundary.name
}

output "access_key_id" {
  value = aws_iam_access_key.boundary.id
}

output "secret_access_key" {
  value     = aws_iam_access_key.boundary.secret
  sensitive = true
}

output "user_name" {
  description = "The name of the user created by this module."
  value       = aws_iam_user.boundary.name
}
