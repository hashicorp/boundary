# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "repository" {
  description = "The GitHub repository, either boundary, boundary-enterprise, or boundary-hcp"
  type        = string
  validation {
    condition     = contains(["boundary", "boundary-enterprise", "boundary-hcp"], var.repository)
    error_message = "Invalid repository, only boundary, boundary-enterprise, and boundary-hcp are supported"
  }
}
