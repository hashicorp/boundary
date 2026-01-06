# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

variable "common_tags" {
  description = "A map of tags to set for the S3 bucket."
  type        = map(string)
  default     = { "Project" : "Enos" }
}

variable "cluster_tag" {
  description = "The cluster_tag from the Boundary cluster module."
  type        = string
}

variable "is_user" {
  description = "Boolean to specify if a user was provided to this module."
  type        = bool
  default     = false
}

variable "user" {
  description = "A username that will be allowed access to this module's bucket."
  type        = string
  default     = ""
}
