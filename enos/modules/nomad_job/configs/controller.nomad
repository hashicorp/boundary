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

variable "count" {
  description = "Number of controllers to create"
  type = number
  default = 3
}

job "controller" {
  datacenters = ["dc1"]

  group "controller" {
    count = var.count

    restart {
      attempts = 3
      delay    = "30s"
    }

    network {
      port "api" {
        to = 9200
      }
      port "cluster" {
        to = 9201
      }
      port "proxy" {
        to = 9202
      }
      port "ops" {
        to = 9203
      }
    }

    network {
    port "redis" { to = 6379 }
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

      service {
        tags = ["boundary"]

      }
    }
  }
}
