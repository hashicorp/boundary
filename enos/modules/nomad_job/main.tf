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
  configs = [for i, _ in range(var.controller_groups_count) : {
    init = {
      content     = "${path.module}/configs/init.nomad.tftpl"
      destination = "/tmp/init_${i}.nomad"
    }
    controller = {
      content     = "${path.module}/configs/controller.nomad.tftpl"
      destination = "/tmp/controller_${i}.nomad"
    }
  }]
  traefik_job_spec_path = "/tmp/traefik.nomad"
}

resource "enos_file" "boundary_controller_job" {
  count = var.controller_groups_count

  content = templatefile(local.configs[count.index].controller.content, {
    cluster_id  = count.index
    db_username = var.db_username
    db_password = var.db_password
    db_address  = var.db_address
    db_name     = var.db_name
    count       = var.controller_count
  })
  destination = local.configs[count.index].controller.destination

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = var.nomad_instances[0]
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_file" "boundary_init_job" {
  count = var.controller_groups_count

  content = templatefile(local.configs[count.index].init.content, {
    cluster_id  = count.index
    db_username = var.db_username
    db_password = var.db_password
    db_address  = var.db_address
    db_name     = var.db_name
  })
  destination = local.configs[count.index].init.destination

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = var.nomad_instances[0]
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_file" "traefik_job" {
  source      = abspath("${path.module}/configs/traefik.nomad")
  destination = local.traefik_job_spec_path

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = var.nomad_instances[0]
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_remote_exec" "init_job" {
  count = var.controller_groups_count

  environment = {
    NOMAD_VAR_db_username = var.db_username
    NOMAD_VAR_db_password = var.db_password
    NOMAD_VAR_db_address  = "${var.db_address}_${count.index}"
    NOMAD_VAR_db_name     = "${var.db_name}_${count.index}"
    JOB_PATH              = local.configs[count.index].init.destination
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
  count = var.controller_groups_count

  environment = {
    NOMAD_VAR_db_username = var.db_username
    NOMAD_VAR_db_password = var.db_password
    NOMAD_VAR_db_address  = "${var.db_address}_${count.index}"
    NOMAD_VAR_db_name     = "${var.db_name}_${count.index}"
    JOB_PATH              = local.configs[count.index].controller.destination
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

resource "enos_remote_exec" "traefik_job" {
  environment = {
    JOB_PATH = local.traefik_job_spec_path
  }

  scripts = [abspath("${path.module}/scripts/deploy-job.sh")]

  transport = {
    ssh = {
      host = var.nomad_instances[0]
    }
  }

  depends_on = [
    enos_remote_exec.init_job,
    enos_remote_exec.controller_job
  ]
}
