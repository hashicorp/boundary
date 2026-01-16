# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

variable "repository" {
  description = "The GitHub repository, either boundary, boundary-enterprise, or boundary-hcp"
  type        = string
  validation {
    condition     = contains(["boundary", "boundary-enterprise", "boundary-hcp"], var.repository)
    error_message = "Invalid repository, only boundary, boundary-enterprise, and boundary-hcp are supported"
  }
}
