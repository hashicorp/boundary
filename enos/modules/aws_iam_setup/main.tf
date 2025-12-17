# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

data "aws_caller_identity" "current" {}

variable "test_id" {}
variable "test_email" {}
variable "enable_credential_rotation" {
  description = "Sets up the IAM user to support the use of credential rotation in Boundary"
  type        = bool
  default     = false
}


locals {
  # Use the AWS provided email if users are running this, override with variable for CI
  user_email = var.test_email == null ? split(":", data.aws_caller_identity.current.user_id)[1] : var.test_email
}

resource "aws_iam_user" "boundary" {
  name                 = "demo-${local.user_email}-${var.test_id}"
  tags                 = { boundary-demo = local.user_email }
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/DemoUser"
  # If credential rotation is used, this is necessary to delete the user since a new access
  # key will be generated.
  force_destroy = var.enable_credential_rotation ? true : false
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

resource "aws_iam_user_policy" "rotate_keys" {
  count = var.enable_credential_rotation ? 1 : 0
  name  = "boundary_e2e_${var.test_id}_rotate_keys"
  user  = aws_iam_user.boundary.name
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "iam:DeleteAccessKey",
          "iam:GetUser",
          "iam:CreateAccessKey"
        ],
        "Effect" : "Allow",
        "Resource" : "${aws_iam_user.boundary.arn}",
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
  value = nonsensitive(aws_iam_access_key.boundary.secret)
}

output "user_name" {
  description = "The name of the user created by this module."
  value       = aws_iam_user.boundary.name
}
