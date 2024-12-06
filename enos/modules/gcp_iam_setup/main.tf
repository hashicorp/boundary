# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

data "google_client_openid_userinfo" "current" {}

variable "test_id" {}
variable "test_email" {}
variable "gcp_project_id" {}
variable "rolesList" {
  type        = list(string)
  description = "List of roles to assign to the service account"
  default     = ["roles/compute.viewer", "roles/iam.serviceAccountKeyAdmin"]
}

locals {
  user_email        = var.test_email == null ? data.google_client_openid_userinfo.current.email : var.test_email
  user_email_prefix = substring(replace(split("@", local.user_email)[0], ".", "-"), 0, 10)
}

resource "random_id" "service_account_client_email" {
  prefix      = "enos-${local.user_email_prefix}"
  byte_length = 2
}

resource "google_service_account" "enos_service_account" {
  account_id   = random_id.service_account_client_email.dec
  display_name = "enos-${local.user_email_prefix}"
}

resource "google_project_iam_binding" "enos_service_account_user" {
  count   = length(var.rolesList)
  project = var.gcp_project_id
  role    = var.rolesList[count.index]
  members = [
    "serviceAccount:${google_service_account.enos_service_account.email}"
  ]
}

resource "google_service_account_key" "enos_service_account_key" {
  service_account_id = google_service_account.enos_service_account.name
  public_key_type    = "TYPE_X509_PEM_FILE"
  private_key_type   = "TYPE_GOOGLE_CREDENTIALS_FILE"
  key_algorithm      = "KEY_ALG_RSA_2048"
}

output "gcp_private_key" {
  value     = jsondecode(base64decode(google_service_account_key.enos_service_account_key.private_key)).private_key
  sensitive = true
}

output "gcp_private_key_id" {
  value = chomp(reverse(split("/", google_service_account_key.enos_service_account_key.id))[0])
}

output "gcp_client_email" {
  value = google_service_account.enos_service_account.email
}