# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

locals {
  stack = {
    "4"    = "ipv4",
    "dual" = "dualstack",
    "6"    = "dualstack-without-public-ipv4",
  }
}

resource "aws_alb" "boundary_alb" {
  name            = "boundary-alb-${random_string.cluster_id.result}"
  depends_on      = [aws_instance.controller]
  security_groups = [aws_security_group.boundary_alb_sg.id]
  subnets         = data.aws_subnets.infra.ids

  ip_address_type = lookup(local.stack, var.ip_version, local.stack["4"])

  tags = merge(local.common_tags,
    {
      Name = "boundary-alb-${random_string.cluster_id.result}"
    }
  )
}

resource "tls_private_key" "private_key" {
  depends_on = [aws_alb.boundary_alb]
  count      = var.protocol == "https" ? 1 : 0

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "certificate" {
  depends_on = [aws_alb.boundary_alb]
  count      = var.protocol == "https" ? 1 : 0

  private_key_pem = tls_private_key.private_key[0].private_key_pem

  subject {
    common_name = aws_alb.boundary_alb.dns_name
  }

  dns_names = [aws_alb.boundary_alb.dns_name]

  validity_period_hours = 8760

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "aws_acm_certificate" "cert" {
  depends_on = [aws_alb.boundary_alb]
  count      = var.protocol == "https" ? 1 : 0

  private_key      = tls_private_key.private_key[0].private_key_pem
  certificate_body = tls_self_signed_cert.certificate[0].cert_pem
}

resource "aws_alb_target_group" "boundary_tg" {
  depends_on      = [aws_acm_certificate.cert]
  name            = "boundary-tg-${random_string.cluster_id.result}"
  protocol        = "HTTP"
  port            = var.listener_api_port
  vpc_id          = var.vpc_id
  ip_address_type = var.ip_version == "6" ? "ipv6" : "ipv4"

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
  protocol          = var.protocol == "https" ? "HTTPS" : "HTTP"

  # These MUST be null if protocol is HTTP
  ssl_policy      = var.protocol == "https" ? "ELBSecurityPolicy-2016-08" : null
  certificate_arn = var.protocol == "https" ? aws_acm_certificate.cert[0].arn : null

  default_action {
    target_group_arn = aws_alb_target_group.boundary_tg.arn
    type             = "forward"
  }
}
