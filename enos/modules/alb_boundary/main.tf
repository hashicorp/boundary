resource "aws_security_group" "boundary_ingress_sg" {
  vpc_id = var.vpc_id

  # Boundary
  dynamic "ingress" {
    for_each = local.open_ports
    content {
      description = ingress.value["description"]
      from_port   = ingress.value["port"]
      to_port     = ingress.value["port"]
      protocol    = "tcp"
      cidr_blocks = var.cidr_blocks
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = var.cluster_name
  }
}

resource "aws_lb" "boundary_clients_ingress" {
  security_groups = [aws_security_group.boundary_ingress_sg.id]
  subnets         = [for k, _ in var.vpc_subnets : k]
  tags = {
    Name = var.cluster_name
  }
}

resource "aws_lb_listener" "boundary_listener" {
  load_balancer_arn = aws_lb.boundary_clients_ingress.id
  port              = local.boundary_port

  default_action {
    type = "forward"

    forward {
      target_group {
        arn = aws_lb_target_group.boundary_clients.arn
      }
    }
  }

  tags = {
    Name = var.cluster_name
  }
}

resource "aws_lb_target_group" "boundary_clients" {
  port     = local.boundary_port
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    port = var.health_check_port
    path = var.health_check_path
    matcher = "200"
  }

  tags = {
    Name = var.cluster_name
  }
}

resource "aws_lb_target_group_attachment" "boundary_clients" {
  count = length(var.instance_ids)

  target_group_arn = aws_lb_target_group.boundary_clients.arn
  target_id        = var.instance_ids[count.index]
  port             = local.boundary_port
}

output "alb_fqdn" {
  value = aws_lb.boundary_clients_ingress.dns_name
}

output "cluster_name_tag" {
  value = var.cluster_name
}
