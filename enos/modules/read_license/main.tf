# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1


# Loads boundary license from file or environment variable
# If license is null or not provided, then the license is returned from the file at license_path
variable "license_path" {
  description = "Path to the boundary license file"
}
variable "license" {
  description = "Boundary license"
  default     = null
}

output "license" {
  value = var.license != null ? var.license : file(var.license_path)
}
