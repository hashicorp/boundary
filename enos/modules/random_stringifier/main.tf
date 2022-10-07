variable "length" {
  type    = number
  default = 10
}
resource "random_string" "string" {
  length  = var.length
  lower   = true
  upper   = true
  numeric = true
  special = false
}

output "string" {
  value = random_string.string.result
}
