# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "ci_roles" {
  value = [{
    name   = aws_iam_role.role.name
    arn    = aws_iam_role.role.arn
    policy = aws_iam_role_policy.role_policy.policy
  }]
}
