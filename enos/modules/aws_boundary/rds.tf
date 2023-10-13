# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "aws_db_subnet_group" "boundary" {
  name       = "boundary-db-subnet-${random_string.cluster_id.result}"
  subnet_ids = data.aws_subnets.infra.ids
}

resource "aws_db_instance" "boundary" {
  count               = var.db_create == true ? 1 : 0
  identifier          = "boundary-db-${random_string.cluster_id.result}"
  allocated_storage   = var.db_storage
  storage_type        = var.db_storage_type
  iops                = var.db_storage_iops
  engine              = var.db_engine
  engine_version      = var.db_engine == "aurora-postgres" ? null : var.db_version
  instance_class      = var.db_class
  monitoring_interval = var.db_monitoring_interval
  monitoring_role_arn = var.db_monitoring_role_arn
  publicly_accessible = true
  db_name             = local.db_name

  // username and password must not be provided when restoring from a snapshot
  username                     = local.is_restored_db ? null : var.db_user
  password                     = local.is_restored_db ? null : var.db_pass
  port                         = var.db_port
  skip_final_snapshot          = true
  db_subnet_group_name         = aws_db_subnet_group.boundary.name
  vpc_security_group_ids       = [aws_security_group.boundary_db_sg.id]
  apply_immediately            = true
  snapshot_identifier          = var.db_snapshot_identifier
  performance_insights_enabled = true
  tags = merge(local.common_tags,
    {
      Name = "boundary-db-${random_string.cluster_id.result}"
      Type = local.boundary_cluster_tag
    },
  )
}
