terraform {
  required_providers {
    enos = {
      source  = "hashicorp.com/qti/enos"
      version = ">= 0.2.1"
    }
  }
}

data "enos_environment" "localhost" {}

data "aws_vpc" "infra" {
  id = var.vpc_id
}

data "aws_subnets" "infra" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }
}

locals {
  name_suffix          = "${var.project_name}-${var.environment}"
  boundary_cluster_tag = "boundary-server-${var.cluster_id}"
}

resource "aws_db_subnet_group" "boundary" {
  name       = "boundary-db-subnet-${var.cluster_id}"
  subnet_ids = data.aws_subnets.infra.ids
}

resource "aws_security_group" "boundary_db_sg" {
  name        = "boundary-db-sg-${var.cluster_id}"
  description = "Postgres Traffic"
  vpc_id      = var.vpc_id

  ingress {
    cidr_blocks      = ["${data.enos_environment.localhost.public_ip_address}/32", join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block)]
    description      = "database"
    from_port        = 5432
    to_port          = 5432
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    protocol         = "tcp"
    self             = null
    security_groups  = []
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_suffix}-boundary-db-sg"
    },
  )
}

resource "aws_db_instance" "boundary" {
  count                  = var.db_create == true ? 1 : 0
  identifier             = "boundary-db-${var.cluster_id}"
  allocated_storage      = var.db_storage
  storage_type           = var.db_storage_type
  iops                   = var.db_storage_iops
  engine                 = var.db_engine
  engine_version         = var.db_engine == "aurora-postgres" ? null : var.db_version
  instance_class         = var.db_class
  monitoring_interval    = var.db_monitoring_interval
  monitoring_role_arn    = var.db_monitoring_role_arn
  publicly_accessible    = true
  db_name                = var.db_name
  username               = var.db_user
  password               = var.db_pass
  port                   = var.db_port
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.boundary.name
  vpc_security_group_ids = [aws_security_group.boundary_db_sg.id]
  apply_immediately      = true
  snapshot_identifier    = var.db_snapshot_identifier
  tags = merge(
    var.common_tags,
    {
      Name = "boundary-db-${var.cluster_id}",
      Type = local.boundary_cluster_tag,
    },
  )
}
