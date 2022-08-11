variable "db_username" {
  description = "The boundary database username"
  type        = string
}

variable "db_password" {
  description = "The boundary database password"
  type        = string
}

variable "db_address" {
  description = "The boundary database address"
  type        = string
}

variable "db_name" {
  description = "The name of the boundary database to connect to when initializing boundary"
  type        = string
}

job "init" {
  datacenters = ["dc1"]
  type        = "batch"
  group "init" {
    task "init" {
      driver = "docker"

      config {
        image          = "hashicorp/boundary"
        auth_soft_fail = true
        command        = "boundary"
        args           = ["database", "init", "-config", "/boundary/config.hcl", "-format", "json"]
      }

      env {
        BOUNDARY_POSTGRES_URL = format("postgresql://%s:%s@%s:5432/%s?sslmode=disable", var.db_username, var.db_password, var.db_address, var.db_name)
      }

      lifecycle {
        hook    = "prestart"
        sidecar = false
      }
    }
  }
}
