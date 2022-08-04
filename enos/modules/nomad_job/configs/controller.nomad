

job "boundary-controller" {
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
        BOUNDARY_POSTGRES_URL = "postgresql://username:password@fqdn:5432/dbname?sslmode=disable"
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
        BOUNDARY_POSTGRES_URL = "postgresql://postgres:hunter2!@joshb-test.cybzv9aeiqzg.us-east-1.rds.amazonaws.com:5432/postgres?sslmode=disable"
      }

      resources {
        cpu    = 500
        memory = 256
      }
    }
  }
}

