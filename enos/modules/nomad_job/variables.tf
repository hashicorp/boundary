variable "private_key_path" {
  type        = string
  description = "The fully qualified path to a local private key for use with the AWS keypair"
}


variable "nomad_instances" {
  description = "Public IPs of Nomad instances"
  type        = list(string)
}

variable "db_username" {
  description = "The username to use when connecting to the boundary database"
  type        = string
}

variable "db_password" {
  description = "The password to use when connecting to the boundary database"
  type        = string
  sensitive   = true
}

variable "db_address" {
  description = "The address of the boundary database"
  type        = string
}
