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

locals {
  controller_job_spec_path = "/tmp/controller.nomad"
  init_job_spec_path       = "/tmp/init.nomad"
}

resource "enos_file" "boundary_controller_job" {
  source      = abspath("${path.module}/configs/controller.nomad")
  destination = local.controller_job_spec_path

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = var.nomad_instances[0]
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_file" "boundary_init_job" {
  source      = abspath("${path.module}/configs/init.nomad")
  destination = local.init_job_spec_path

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = var.nomad_instances[0]
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_remote_exec" "init_job" {

  environment = {
    NOMAD_VAR_db_username = var.db_username
    NOMAD_VAR_db_password = var.db_password
    NOMAD_VAR_db_address  = var.db_address
    NOMAD_VAR_db_name     = var.db_name
    JOB_PATH              = local.init_job_spec_path
  }

  scripts = [abspath("${path.module}/scripts/deploy-job.sh")]

  transport = {
    ssh = {
      host = var.nomad_instances[0]
    }
  }

  depends_on = [
    enos_file.boundary_init_job
  ]
}

resource "enos_remote_exec" "controller_job" {

  environment = {
    NOMAD_VAR_db_username = var.db_username
    NOMAD_VAR_db_password = var.db_password
    NOMAD_VAR_db_address  = var.db_address
    NOMAD_VAR_db_name     = var.db_name
    JOB_PATH              = local.controller_job_spec_path
  }

  scripts = [abspath("${path.module}/scripts/deploy-job.sh")]

  transport = {
    ssh = {
      host = var.nomad_instances[0]
    }
  }

  depends_on = [
    enos_remote_exec.init_job,
    enos_file.boundary_controller_job
  ]
}
