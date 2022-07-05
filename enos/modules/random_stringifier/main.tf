

resource "random_string" "string" {
  length  = 10
  lower   = true
  upper   = true
  numeric = true
  special = false
}

output "string" {
  value = random_string.string.result
}
