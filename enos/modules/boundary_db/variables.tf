variable "project_name" {
  description = "Name of the project."
  type        = string
}

variable "environment" {
  description = "Name of the environment. (CI/Dev/Test/etc)"
  type        = string
}

variable "cluster_id" {
  description = "The id of the boundary cluster"
  type        = string
}

variable "common_tags" {
  description = "Tags to set for all resources"
  type        = map(string)
}

variable "vpc_id" {
  description = "The id of the vpc to use for rds"
  type        = string
}

variable "db_class" {
  description = "AWS RDS DB instance class (size/type)"
  type        = string
  default     = "db.t4g.small"
}

variable "db_version" {
  description = "AWS RDS DBS engine version (for postgres/mysql)"
  type        = string
  default     = "14.2"
}

variable "db_engine" {
  description = "AWS RDS DB engine type"
  type        = string
  default     = "postgres"
}

variable "db_storage" {
  description = "AWS RDS DB storage volume (in GB)"
  type        = number
  default     = 10
}

variable "db_storage_type" {
  description = "AWS RDS DB storage type"
  type        = string
  default     = "gp2"
}

variable "db_storage_iops" {
  description = "AWS RDS DB storage IOPS (optional)"
  type        = string
  default     = null
}

variable "db_name" {
  description = "Name of the RDS Database"
  type        = string
  default     = "boundary"
}

variable "db_create" {
  description = "Enables module to create RDS resources"
  type        = bool
  default     = true
}

variable "db_host" {
  description = "Address of a pre-configured PostgreSQL host"
  type        = string
  default     = null
}

variable "db_port" {
  description = "Address of a pre-configured PostgreSQL host"
  type        = number
  default     = 5432
}

variable "db_user" {
  description = "Default username for RDS database"
  type        = string
  default     = "boundary"
}

variable "db_pass" {
  description = "Default password for RDS database"
  type        = string
  default     = ""
}

variable "db_monitoring_interval" {
  description = "Interval (in seconds) to report enhanced DB metrics. Disabled by default"
  type        = number
  default     = 0
}

variable "db_monitoring_role_arn" {
  description = "The ARN of the IAM role to be used to report enhanced DB metrics. Must be set if db_monitoring_interval is set"
  type        = string
  default     = ""
}

variable "db_max_open_connections" {
  description = "The maximum number of open connections to the database. Limiting this limits the load a controller can handle."
  type        = number
  default     = 5

  validation {
    condition     = var.db_max_open_connections >= 5
    error_message = "Max open connections must be at least 5."
  }
}

variable "db_snapshot_identifier" {
  description = "The name of the DB snapshot to restore into the created RDS instance. Will be applied to all clusters created. If not set, no DB restore will be made."
  type        = string
  default     = null
}
