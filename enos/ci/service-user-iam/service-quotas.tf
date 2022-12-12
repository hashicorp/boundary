locals {
  subnets_per_vpc          = "L-F678F1CE"
  rds_max_db_subnet_groups = "L-48C6BF61"
}

resource "aws_servicequotas_service_quota" "vpcs_pre_region_us_east_1" {
  provider     = aws.us_east_1
  quota_code   = local.subnets_per_vpc
  service_code = "vpc"
  value        = 50
}

resource "aws_servicequotas_service_quota" "rds_subnet_groups_us_east_1" {
  provider     = aws.us_east_1
  quota_code   = local.rds_max_db_subnet_groups
  service_code = "rds"
  value        = 50
}

resource "aws_servicequotas_service_quota" "vpcs_pre_region_us_east_2" {
  provider     = aws.us_east_2
  quota_code   = local.subnets_per_vpc
  service_code = "vpc"
  value        = 50
}

resource "aws_servicequotas_service_quota" "rds_subnet_groups_us_east_2" {
  provider     = aws.us_east_2
  quota_code   = local.rds_max_db_subnet_groups
  service_code = "rds"
  value        = 50
}

resource "aws_servicequotas_service_quota" "vpcs_pre_region_us_west_1" {
  provider     = aws.us_west_1
  quota_code   = local.subnets_per_vpc
  service_code = "vpc"
  value        = 50
}

resource "aws_servicequotas_service_quota" "rds_subnet_groups_us_west_1" {
  provider     = aws.us_west_1
  quota_code   = local.rds_max_db_subnet_groups
  service_code = "rds"
  value        = 50
}

resource "aws_servicequotas_service_quota" "vpcs_pre_region_us_west_2" {
  provider     = aws.us_west_2
  quota_code   = local.subnets_per_vpc
  service_code = "vpc"
  value        = 50
}

resource "aws_servicequotas_service_quota" "rds_subnet_groups_us_west_2" {
  provider     = aws.us_west_2
  quota_code   = local.rds_max_db_subnet_groups
  service_code = "rds"
  value        = 50
}
