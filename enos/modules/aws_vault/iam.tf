# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

data "aws_iam_policy_document" "vault_instance_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "vault_profile" {
  statement {
    resources = ["*"]

    actions = [
      "ec2:DescribeInstances",
      "secretsmanager:*"
    ]
  }

  statement {
    resources = [var.kms_key_arn]

    actions = [
      "kms:DescribeKey",
      "kms:ListKeys",
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ]
  }
}

resource "aws_iam_role" "vault_instance_role" {
  name               = "vault_instance_role-${random_string.cluster_id.result}"
  assume_role_policy = data.aws_iam_policy_document.vault_instance_role.json
}

resource "aws_iam_instance_profile" "vault_profile" {
  name = "vault_instance_profile-${random_string.cluster_id.result}"
  role = aws_iam_role.vault_instance_role.name
}

resource "aws_iam_role_policy" "vault_policy" {
  name   = "vault_policy-${random_string.cluster_id.result}"
  role   = aws_iam_role.vault_instance_role.id
  policy = data.aws_iam_policy_document.vault_profile.json
}
