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

variable "db_name" {
  description = "The name of the boundary database to connect to when initializing Boundary"
  type        = string
}

variable "controller_groups_count" {
  description = "The amount of unique Boundary instances to spin up"
  type        = number
  default     = 2
}

variable "controller_count" {
  description = "The amount of Boundary controllers to spin up for each controller group"
  type        = number
  default     = 3
}
