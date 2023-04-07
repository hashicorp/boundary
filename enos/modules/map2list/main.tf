variable "map" {}

output "list" {
  value = keys(var.map)
}
