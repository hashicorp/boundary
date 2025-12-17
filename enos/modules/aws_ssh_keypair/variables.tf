# Copyright IBM Corp. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

variable "enos_user" {
  description = "The user running the tests, this is by default your OS user or Github User"
  type        = string
}