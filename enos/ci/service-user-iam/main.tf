terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }

  cloud {
    hostname     = "app.terraform.io"
    organization = "hashicorp-qti"
    // workspace must be exported in the environment as: TF_WORKSPACE=<boundary|boundary-enterprise>-ci-enos-service-user-iam
  }
}

locals {
  enterprise_repositories = ["boundary-enterprise", "boundary-hcp"]
  is_ent                  = contains(local.enterprise_repositories, var.repository)
  service_user            = "github_actions-boundary_ci"
  oss_aws_account_id      = "271311691044"
}

resource "aws_iam_role" "role" {
  count = local.is_ent ? 0 : 1 // only create a role for the OSS repositories

  provider = aws.us_east_1

  name               = local.service_user
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy_document[0].json
}

data "aws_iam_policy_document" "assume_role_policy_document" {
  count = local.is_ent ? 0 : 1 // only create a policy for the OSS repositories

  provider = aws.us_east_1

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.oss_aws_account_id}:user/${local.service_user}"]
    }
  }
}

resource "aws_iam_role_policy" "role_policy" {
  count = local.is_ent ? 0 : 1 // only create a policy for the OSS repositories

  provider = aws.us_east_1

  role   = aws_iam_role.role[0].name
  name   = "${local.service_user}_policy"
  policy = data.aws_iam_policy_document.iam_policy_document.json
}

data "aws_iam_policy_document" "iam_policy_document" {
  provider = aws.us_east_1

  statement {
    effect = "Allow"
    actions = [
      "iam:ListRoles",
      "iam:CreateRole",
      "iam:GetRole",
      "iam:DeleteRole",
      "iam:ListInstanceProfiles",
      "iam:ListInstanceProfilesForRole",
      "iam:CreateInstanceProfile",
      "iam:GetInstanceProfile",
      "iam:DeleteInstanceProfile",
      "iam:ListPolicies",
      "iam:CreatePolicy",
      "iam:DeletePolicy",
      "iam:ListRoles",
      "iam:CreateRole",
      "iam:AddRoleToInstanceProfile",
      "iam:PassRole",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:DeleteRole",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:AttachRolePolicy",
      "iam:GetRolePolicy",
      "iam:PutRolePolicy",
      "iam:DetachRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:ListUsers",
      "iam:GetUser",
      "iam:GetUserId",
      "iam:DescribeUser",
      "iam:DeleteUser",
      "iam:CreateUser",
      "iam:TagUser",
      "iam:UntagUser",
      "iam:ListUserTags",
      "iam:CreateUserTag",
      "iam:DeleteUserTag",
      "iam:ListUserPolicies",
      "iam:CreateUserPolicy",
      "iam:PutUserPolicy",
      "iam:DeleteUserPolicy",
      "iam:ListGroupsForUser",
      "iam:ListAccessKeys",
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeInstanceTypeOfferings",
      "ec2:DescribeInstanceCreditSpecifications",
      "ec2:DescribeImages",
      "ec2:DescribeTags",
      "ec2:DescribeVpcClassicLink",
      "ec2:DescribeVpcClassicLinkDnsSupport",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeSecurityGroups",
      "ec2:CreateSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:DeleteSecurityGroup",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceAttribute",
      "ec2:CreateTags",
      "ec2:RunInstances",
      "ec2:ModifyInstanceAttribute",
      "ec2:TerminateInstances",
      "ec2:ResetInstanceAttribute",
      "ec2:DeleteTags",
      "ec2:DescribeVolumes",
      "ec2:CreateVolume",
      "ec2:DeleteVolume",
      "ec2:DescribeVpcs",
      "ec2:DescribeVpcAttribute",
      "ec2:CreateVPC",
      "ec2:ModifyVPCAttribute",
      "ec2:DeleteVPC",
      "ec2:DescribeSubnets",
      "ec2:CreateSubnet",
      "ec2:ModifySubnetAttribute",
      "ec2:DeleteSubnet",
      "ec2:DescribeInternetGateways",
      "ec2:CreateInternetGateway",
      "ec2:AttachInternetGateway",
      "ec2:DetachInternetGateway",
      "ec2:DeleteInternetGateway",
      "ec2:DescribeRouteTables",
      "ec2:CreateRoute",
      "ec2:CreateRouteTable",
      "ec2:AssociateRouteTable",
      "ec2:DisassociateRouteTable",
      "ec2:DeleteRouteTable",
      "ec2:CreateKeyPair",
      "ec2:ImportKeyPair",
      "ec2:DeleteKeyPair",
      "ec2:DescribeKeyPairs",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
      "elasticloadbalancing:AttachLoadBalancerToSubnets",
      "elasticloadbalancing:ConfigureHealthCheck",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteRule",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:ModifyRule",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:RemoveTags",
      "elasticloadbalancing:SetRulePriorities",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "kms:ListKeys",
      "kms:ListResourceTags",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:DescribeKey",
      "kms:CreateKey",
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ScheduleKeyDeletion",
      "kms:ListAliases",
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "rds:DescribeDBSubnetGroups",
      "rds:CreateDBSubnetGroup",
      "rds:ModifyDBSubnetGroup",
      "rds:DeleteDBSubnetGroup",
      "rds:DescribeDBInstances",
      "rds:CreateDBInstance",
      "rds:ModifyDBInstance",
      "rds:DeleteDBInstance",
      "rds:ListTagsForResource",
      "rds:AddTagsToResource",
      "rds:RemoveTagsFromResource",
    ]
    resources = ["*"]
  }
}
