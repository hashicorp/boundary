variable "vpc_id" {
  description = "The VPC ID for instances using the ALB"
  type        = string
}

variable "lb_name_suffix" {
  description = "The suffix for the load balancer's name"
  type        = string
  default     = "boundary"
}

variable "cidr_blocks" {
  description = "The allowed external CIDR blocks for the Security Group"
  type        = list(string)
}

variable "instance_ids" {
  description = "A list of aws_instance IDs, e.g. [\"i-01b0133d2f5c72465\",\"i-02a7f0b8f4a410c89\",\"i-09048b63084a0b9ba\"]"
  type        = list(string)
}

variable "vpc_subnets" {
  description = "A map of subnet IDs to CIDR blocks for use with the ALB"
  type        = any
}
