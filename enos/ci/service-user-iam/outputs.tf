output "ci_role" {
  value = local.is_ent ? {
    name = aws_iam_role.github_actions_doormat_role[0].name
    arn  = aws_iam_role.github_actions_doormat_role[0].arn
    } : {
    name = aws_iam_role.role[0].name
    arn  = aws_iam_role.role[0].arn
  }
}

output "ci_role_policy" {
  value = local.is_ent ? {
    name   = local.github_actions_doormat_assume_policy_name
    policy = data.aws_iam_policy_document.github_actions_doormat_assume[0].json
    } : {
    name   = aws_iam_role_policy.role_policy[0].name
    policy = aws_iam_role_policy.role_policy[0].policy
  }
}
