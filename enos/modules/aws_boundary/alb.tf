# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "aws_alb" "boundary_alb" {
  name            = "boundary-alb-${random_string.cluster_id.result}"
  depends_on      = [aws_instance.controller]
  security_groups = [aws_security_group.boundary_alb_sg.id]
  subnets         = data.aws_subnets.infra.ids
  tags = merge(local.common_tags,
    {
      Name = "boundary-alb-${random_string.cluster_id.result}"
    }
  )
}

resource "aws_alb_target_group" "boundary_tg" {
  name     = "boundary-tg-${random_string.cluster_id.result}"
  port     = var.listener_api_port
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    path              = var.healthcheck_path
    port              = var.listener_ops_port
    interval          = 5
    timeout           = 2
    healthy_threshold = 2
  }
  tags = merge(local.common_tags,
    {
      Name = "boundary-tg-${random_string.cluster_id.result}"
    },
  )
}

resource "aws_lb_target_group_attachment" "boundary" {
  for_each = toset([for idx in range(var.controller_count) : tostring(idx)])

  target_group_arn = aws_alb_target_group.boundary_tg.arn
  target_id        = aws_instance.controller[each.value].id
  port             = var.listener_api_port
}

resource "aws_alb_listener" "boundary" {
  load_balancer_arn = aws_alb.boundary_alb.arn
  port              = var.alb_listener_api_port
  protocol          = "HTTP"
  default_action {
    target_group_arn = aws_alb_target_group.boundary_tg.arn
    type             = "forward"
  }
}
