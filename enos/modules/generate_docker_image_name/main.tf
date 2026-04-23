# Copyright IBM Corp. 2020, 2026
# SPDX-License-Identifier: BUSL-1.1

variable "image_tag" {
  description = "the tag of the docker image (e.g. 1.2.3)"
  type        = string
  default     = "latest"
}

variable "edition" {
  description = "the edition of the docker image, either 'oss' or 'ent'"
  type        = string
  default     = "oss"
  validation {
    condition     = contains(["oss", "ent"], var.edition)
    error_message = "edition must be either 'oss' or 'ent'."
  }
}

variable "repository" {
  description = "the repository of the docker image."
  type        = string
  default     = "hashicorp/boundary"
}

output "image_name" {
  value = "${var.repository}${var.edition == "ent" ? "-enterprise" : ""}:${var.image_tag}${var.edition == "ent" ? "-ent" : ""}"
}
