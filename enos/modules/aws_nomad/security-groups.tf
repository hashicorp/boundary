resource "aws_security_group" "enos_nomad_sg" {
  name        = "nomad-sg-${random_string.cluster_id.result}"
  description = "SSH, Consul, and Nomad traffic"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = local.open_ports
    content {
      description = ingress.value["description"]
      from_port   = ingress.value["from"]
      to_port     = ingress.value["to"]
      protocol    = ingress.value["protocol"]
      cidr_blocks = local.cidr_blocks
    }
  }

  ingress {
    description = "Internal traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    description = "All outgoing traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_suffix}-nomad-sg"
    },
  )
}
