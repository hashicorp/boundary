
output "db_username" {
  value       = aws_db_instance.boundary[0].username
  description = "the database username to use when connecting to boundary database"
}

output "db_password" {
  value       = aws_db_instance.boundary[0].password
  description = "the database password to use when connecting to the the boundary database"
  sensitive   = true
}

output "db_address" {
  value       = aws_db_instance.boundary[0].address
  description = "the database address for the boundary database"
}

output "db_name" {
  value       = var.db_name
  description = "the database name for the boundary database"
}
