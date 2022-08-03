terraform {
  required_providers {
    # We need to specify the provider source in each module until we publish it
    # to the public registry
    enos = {
      version = ">= 0.1.28"
      source  = "hashicorp.com/qti/enos"
    }
  }
}

resource "enos_file" "boundary_controller_job" {
  source      = abspath("${path.module}/configs/controller.nomad")
  destination = "/tmp/controller.nomad"

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = var.nomad_instances[0]
      private_key_path = var.private_key_path
    }
  }
}


resource "enos_remote_exec" "deploy_job" {

  environment = {
    NOMAD_VAR_db_username = var.db_username
    NOMAD_VAR_db_password = var.db_password
    NOMAD_VAR_db_address  = var.db_address
  }

  inline = ["nomad job run /tmp/controller.nomad"]

  transport = {
    ssh = {
      host = var.nomad_instances[0]
    }
  }

  depends_on = [
    enos_file.boundary_controller_job
  ]
}
