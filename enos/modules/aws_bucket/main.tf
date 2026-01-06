# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

resource "random_pet" "default" {}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "default" {
  bucket_prefix = "enos-${random_pet.default.id}-"
  force_destroy = true
  tags = merge(
    local.common_tags,
    {
      User = "${split(":", data.aws_caller_identity.current.user_id)[1]}"
    },
  )
}

resource "aws_s3_bucket_lifecycle_configuration" "example" {
  bucket = aws_s3_bucket.default.id

  rule {
    id = "file_retention"
    expiration {
      days = 7
    }
    status = "Enabled"
    filter {}
  }
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
  count  = var.is_user ? 1 : 0
  name   = "${aws_s3_bucket.default.id}_${var.user}_access"
  user   = var.user
  policy = data.aws_iam_policy_document.default.json
}
