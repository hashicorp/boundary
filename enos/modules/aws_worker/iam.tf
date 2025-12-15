# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

data "aws_iam_policy_document" "boundary_instance_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "boundary_profile" {
  statement {
    resources = ["*"]

    actions = ["ec2:DescribeInstances"]
  }

  statement {
    resources = [var.kms_key_arn]

    actions = [
      "kms:DescribeKey",
      "kms:ListKeys",
      "kms:Encrypt",
      "kms:Decrypt",
    ]
  }
}

data "aws_iam_policy_document" "bucket_policy_document" {
  statement {
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:GetObjectAttributes",
      "s3:ListBucket",
    ]

    resources = [
      "${var.bucket_arn}/*",
      "${var.bucket_arn}",
    ]
  }
}

data "aws_iam_policy_document" "combined_policy_document" {
  source_policy_documents = [
    data.aws_iam_policy_document.boundary_profile.json,
    data.aws_iam_policy_document.bucket_policy_document.json,
  ]
}

resource "aws_iam_role" "boundary_instance_role" {
  name                  = "boundary_instance_role-${random_string.cluster_id.result}"
  assume_role_policy    = data.aws_iam_policy_document.boundary_instance_role.json
  force_detach_policies = true
}

resource "aws_iam_instance_profile" "boundary_profile" {
  name = "boundary_instance_profile-${random_string.cluster_id.result}"
  role = aws_iam_role.boundary_instance_role.name
}

resource "aws_iam_role_policy" "boundary_policy" {
  name   = "boundary_policy-${random_string.cluster_id.result}"
  role   = aws_iam_role.boundary_instance_role.id
  policy = var.bucket_arn != "" ? data.aws_iam_policy_document.combined_policy_document.json : data.aws_iam_policy_document.boundary_profile.json
}
