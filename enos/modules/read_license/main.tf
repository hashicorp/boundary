# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1


# Loads license from file or environment variable
# If license is null or not provided, then the license is returned from the file at license_path
variable "license_path" {
  description = "Path to a boundary license file"
  type        = string
  default     = null
}
variable "license" {
  description = "License key"
  type        = string
  default     = null
}

variable "edition" {
  description = "Edition to determine if license is needed"
  type        = string
  default     = "oss"
  validation {
    condition     = contains(["oss", "ent"], var.edition)
    error_message = "edition must be either 'oss' or 'ent'."
  }
}

check "license_or_license_path_required" {
  assert {
    condition = (
      var.edition == "oss" ||
      var.license != null ||
      var.license_path != null
    )
    error_message = "license_path must be provided when license is not set for non-oss editions."
  }
}

output "license" {
  value = var.edition == "ent" ? (var.license != null ? var.license : file(var.license_path)) : ""
}
