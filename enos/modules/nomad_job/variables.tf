variable "private_key_path" {
  type        = string
  description = "The fully qualified path to a local private key for use with the AWS keypair"
}


variable "nomad_instances" {
  description = "Public IPs of Nomad instances"
  type        = list(string)
}
