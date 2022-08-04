resource "aws_security_group" "boundary_ingress_sg" {
  name   = "${var.lb_name_suffix}-server-lb"
  vpc_id = var.vpc_id

  # Boundary
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "boundary_clients_ingress" {
  name               = "boundary-ingress-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.boundary_ingress_sg.id]
  subnets            = [for k, _ in var.vpc_subnets : k]
}

resource "aws_lb_listener" "boundary_listener" {
  load_balancer_arn = aws_lb.boundary_clients_ingress.id
  port              = 80

  default_action {
    type = "forward"

    forward {
      target_group {
        arn = aws_lb_target_group.boundary_clients.arn
      }
    }
  }
}

resource "aws_lb_target_group" "boundary_clients" {
  name     = "nomad-clients"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  # TODO: what should the health check be?
  health_check {
    port = 80
    path = "/"
    # Mark healthy if redirected
    matcher = "200,301,302"
  }
}

resource "aws_lb_target_group_attachment" "boundary_clients" {
  count = length(var.instance_ids)

  target_group_arn = aws_lb_target_group.boundary_clients.arn
  target_id        = var.instance_ids[count.index]
  port             = 80
}

output "alb_address" {
  value = "http://${aws_lb.boundary_clients_ingress.dns_name}:80"
}
