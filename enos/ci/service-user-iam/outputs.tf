# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "ci_roles" {
  value = local.is_ent ? [for role in aws_iam_role.github_actions_doormat_role : {
    name = role.name
    arn  = role.arn
    policy = [for policy in role.inline_policy : {
      name   = policy.name
      policy = jsondecode(policy.policy)
    }][0]
    }] : [{
    name   = aws_iam_role.role[0].name
    arn    = aws_iam_role.role[0].arn
    policy = aws_iam_role_policy.role_policy[0].policy
  }]
}
