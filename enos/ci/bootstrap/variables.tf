variable "aws_ssh_public_key" {
  description = "The public key to use for the ssh key"
  type        = string
}

variable "repository" {
  description = "The repository to bootstrap the ci for, either 'boundary', 'boundary-enterprise', or 'boundary-hcp'"
  type        = string
  validation {
    condition     = contains(["boundary", "boundary-enterprise", "boundary-hcp"], var.repository)
    error_message = "Repository must be one of either 'vault' or 'vault-enterprise'"
  }
}
