variable "db_username" {
  description = "The boundary database username"
  type = string
}

variable "db_password" {
  description = "The boundary database password"
  type = string
}

variable "db_address" {
  description = "The boundary database address"
  type = string
}

variable "db_name" {
  description = "The name of the boundary database to connect to when initializing boundary"
  type = string
}

job "boundary-controller" {
  count = 3

  restart {
    attempts = 3
    delay    = "30s"
  }

  datacenters = ["dc1"]

  group "controller-docker" {
    network {
      port "api" {
        static = 9200
      }
      port "cluster" {
        static = 9201
      }
      port "proxy" {
        static = 9202
      }
      port "ops" {
        static = 9203
      }
    }

    task "init" {
      driver = "docker"
      config {
        image          = "hashicorp/boundary"
        auth_soft_fail = true
        command = "boundary"
        args = ["database",  "init",  "-config", "/boundary/config.hcl", "-format", "json"]
      }

      env {
        BOUNDARY_POSTGRES_URL = format("postgresql://%s:%s@%s:5432/%s?sslmode=disable", var.db_username, var.db_password, var.db_address, var.db_name)
      }

      lifecycle {
        hook = "prestart"
        sidecar = false
      }
    }

    task "controller" {
      driver = "docker"

      config {
        image          = "hashicorp/boundary"
        ports          = ["api", "cluster", "ops"]
        auth_soft_fail = true
      }

      env {
        BOUNDARY_POSTGRES_URL = format("postgresql://%s:%s@%s:5432/%s?sslmode=disable", var.db_username, var.db_password, var.db_address, var.db_name)
      }

      resources {
        cpu    = 500
        memory = 256
      }
    }
  }
}
