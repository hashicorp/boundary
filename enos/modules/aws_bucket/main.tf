# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "random_pet" "default" {}

resource "aws_s3_bucket" "default" {
  bucket_prefix = "enos-${random_pet.default.id}-"
  force_destroy = true
  tags          = local.common_tags
}

data "aws_iam_policy_document" "default" {
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
      "${aws_s3_bucket.default.arn}/*",
      "${aws_s3_bucket.default.arn}",
    ]
  }
}

resource "aws_iam_user_policy" "default" {
  name   = "${aws_s3_bucket.default.id}_${var.user}_access"
  user   = var.user
  policy = data.aws_iam_policy_document.default.json
}
