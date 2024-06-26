# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "bucket_name" {
  value       = aws_s3_bucket.default.id
  description = "The name of the S3 bucket created by this module."
}

output "bucket_arn" {
  value       = aws_s3_bucket.default.arn
  description = "The ARN of the S3 bucket created by this module."
}
