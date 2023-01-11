# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

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
  service_user            = "github_actions-boundary_ci" # convert to a data source to lookup the service user
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
  policy = data.aws_iam_policy_document.combined_policy_document.json
}

data "aws_iam_policy_document" "combined_policy_document" {
  source_policy_documents = [data.aws_iam_policy_document.enos_policy_document.json, data.aws_iam_policy_document.aws_nuke_policy_document.json]
}

data "aws_iam_policy_document" "enos_policy_document" {
  provider = aws.us_east_1

  statement {
    effect = "Allow"
    actions = [
      "ec2:AssociateRouteTable",
      "ec2:AttachInternetGateway",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateInternetGateway",
      "ec2:CreateKeyPair",
      "ec2:CreateRoute",
      "ec2:CreateRouteTable",
      "ec2:CreateSecurityGroup",
      "ec2:CreateSubnet",
      "ec2:CreateTags",
      "ec2:CreateVolume",
      "ec2:CreateVPC",
      "ec2:DeleteInternetGateway",
      "ec2:DeleteKeyPair",
      "ec2:DeleteRouteTable",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteSubnet",
      "ec2:DeleteTags",
      "ec2:DeleteVolume",
      "ec2:DeleteVPC",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeInstanceCreditSpecifications",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceTypeOfferings",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeKeyPairs",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
      "ec2:DescribeVpcAttribute",
      "ec2:DescribeVpcClassicLink",
      "ec2:DescribeVpcClassicLinkDnsSupport",
      "ec2:DescribeVpcs",
      "ec2:DetachInternetGateway",
      "ec2:DisassociateRouteTable",
      "ec2:ImportKeyPair",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifySubnetAttribute",
      "ec2:ModifyVPCAttribute",
      "ec2:ResetInstanceAttribute",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RunInstances",
      "ec2:TerminateInstances",
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
      "iam:AddRoleToInstanceProfile",
      "iam:AttachRolePolicy",
      "iam:CreateAccessKey",
      "iam:CreateInstanceProfile",
      "iam:CreatePolicy",
      "iam:CreateRole",
      "iam:CreateRole",
      "iam:CreateServiceLinkedRole",
      "iam:CreateUser",
      "iam:CreateUserPolicy",
      "iam:CreateUserTag",
      "iam:DeleteAccessKey",
      "iam:DeleteInstanceProfile",
      "iam:DeletePolicy",
      "iam:DeleteRole",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DeleteUser",
      "iam:DeleteUserPolicy",
      "iam:DeleteUserTag",
      "iam:DescribeUser",
      "iam:DetachRolePolicy",
      "iam:GetInstanceProfile",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:GetUser",
      "iam:GetUserId",
      "iam:ListAccessKeys",
      "iam:ListAttachedRolePolicies",
      "iam:ListGroupsForUser",
      "iam:ListInstanceProfiles",
      "iam:ListInstanceProfilesForRole",
      "iam:ListPolicies",
      "iam:ListRolePolicies",
      "iam:ListRoles",
      "iam:ListRoles",
      "iam:ListUserPolicies",
      "iam:ListUsers",
      "iam:ListUserTags",
      "iam:PassRole",
      "iam:PutRolePolicy",
      "iam:PutUserPolicy",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:TagUser",
      "iam:UntagUser",
      "kms:CreateAlias",
      "kms:CreateKey",
      "kms:Decrypt",
      "kms:DeleteAlias",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListAliases",
      "kms:ListKeys",
      "kms:ListResourceTags",
      "kms:ScheduleKeyDeletion",
      "rds:AddTagsToResource",
      "rds:CreateDBInstance",
      "rds:CreateDBSubnetGroup",
      "rds:DeleteDBInstance",
      "rds:DeleteDBSubnetGroup",
      "rds:DescribeDBInstances",
      "rds:DescribeDBSubnetGroups",
      "rds:ListTagsForResource",
      "rds:ModifyDBInstance",
      "rds:ModifyDBSubnetGroup",
      "rds:RemoveTagsFromResource"
    ]
    resources = ["*"]
  }
}


data "aws_iam_policy_document" "aws_nuke_policy_document" {
  provider = aws.us_east_1
  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeInternetGateways",
      "ec2:DescribeNatGateways",
      "ec2:DescribeRegions",
      "ec2:DescribeVpnGateways",
      "iam:DeleteAccessKey",
      "iam:DeleteUser",
      "iam:DeleteUserPolicy",
      "iam:GetUser",
      "iam:ListAccessKeys",
      "iam:ListAccountAliases",
      "iam:ListGroupsForUser",
      "iam:ListUserPolicies",
      "iam:ListUserTags",
      "iam:ListUsers",
      "iam:UntagUser",
      "servicequotas:ListServiceQuotas"
    ]
    resources = ["*"]
  }
}
