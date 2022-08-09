resource "random_string" "string" {
  length  = 10
  lower   = true
  upper   = var.upper
  numeric = true
  special = false
}

output "string" {
  value = random_string.string.result
}

variable "upper" {
  description = "Whether or not to include upper-case characters"
  type        = string
  default     = true
}
