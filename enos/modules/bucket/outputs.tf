# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "bucket_name" {
  value       = aws_s3_bucket.default.id
  description = "The name of the S3 bucket created by this module."
}
