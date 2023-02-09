# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

locals {
  doormat_service_user_arn = "arn:aws:iam::397512762488:user/doormatServiceUser"
  // "Github Actions Doormat repositories and qualifiers"
  // see: https://docs.prod.secops.hashicorp.services/doormat/gha/
  github_actions_doormat_rwqs = {
    boundary-enterprise = {
      ci           = "github.com/hashicorp/boundary-enterprise@event_name=workflow_dispatch+push:ref=refs/heads/main+refs/heads/release/0.8.x+refs/heads/release/0.10.x+refs/heads/release/0.11.x///event_name=pull_request:base_ref=main+release/0.8.x+release/0.10.x+release/0.11.x",
      ci-bootstrap = "github.com/hashicorp/boundary-enterprise@event_name=schedule"
    }
    boundary-hcp = {
      ci           = "github.com/hashicorp/boundary-hcp@event_name=workflow_dispatch+push:ref=refs/heads/main+refs/heads/release/0.8.x+refs/heads/release/0.10.x+refs/heads/release/0.11.x///event_name=pull_request:base_ref=main+release/0.8.x+release/0.10.x+release/0.11.x",
      ci-bootstrap = "github.com/hashicorp/boundary-hcp@event_name=schedule"
    }
  }
  ent_policies_json = {
    ci           = data.aws_iam_policy_document.enos_policy_document.json
    ci-bootstrap = data.aws_iam_policy_document.combined_policy_document.json
  }
  repo_github_actions_doormat_rwqs = local.is_ent ? local.github_actions_doormat_rwqs[var.repository] : {}
}

// Doormat Github Actions assume policy
data "aws_iam_policy_document" "github_actions_doormat_assume" {
  count = local.is_ent ? 1 : 0

  provider = aws.us_east_1

  statement {
    actions = [
      "sts:AssumeRole",
      "sts:SetSourceIdentity",
      "sts:TagSession"
    ]
    principals {
      type        = "AWS"
      identifiers = [local.doormat_service_user_arn] # infrasec_prod
    }
  }
}

# Doormat Github Actions roles
resource "aws_iam_role" "github_actions_doormat_role" {
  for_each = local.repo_github_actions_doormat_rwqs

  provider = aws.us_east_1

  name = "${var.repository}-GHA-${each.key}"
  tags = {
    hc-service-uri = each.value
  }
  max_session_duration = 43200
  assume_role_policy   = data.aws_iam_policy_document.github_actions_doormat_assume[0].json

  inline_policy {
    name   = "AssumeServiceUserPolicy"
    policy = local.ent_policies_json[each.key]
  }
}
