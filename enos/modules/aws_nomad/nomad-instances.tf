resource "aws_instance" "nomad_instance" {
  for_each               = local.nomad_instances
  ami                    = var.ami_id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.enos_nomad_sg.id]
  subnet_id              = tolist(data.aws_subnets.infra.ids)[each.key % length(data.aws_subnets.infra.ids)]
  key_name               = var.ssh_aws_keypair
  iam_instance_profile   = aws_iam_instance_profile.nomad_profile.name
  tags = merge(
    var.common_tags,
    {
      Name = "${local.name_suffix}-nomad-${var.nomad_node_prefix}-${each.key}"
      Type = local.nomad_cluster_tag
    },
  )
}

resource "enos_remote_exec" "install_dependencies" {
  depends_on = [aws_instance.nomad_instance]
  for_each = toset([
    for idx in local.nomad_instances : idx
    if length(var.dependencies_to_install) > 0
  ])

  content = templatefile("${path.module}/../../templates/install-dependencies.sh", {
    dependencies = join(" ", var.dependencies_to_install)
  })


  transport = {
    ssh = {
      user = var.enos_transport_user
      host = aws_instance.nomad_instance[each.value].public_ip
    }
  }
}


resource "enos_bundle_install" "consul" {
  for_each = {
    for idx, instance in aws_instance.nomad_instance : idx => instance
  }

  destination = var.consul_install_dir
  release     = merge(var.consul_release, { product = "consul" })

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = each.value.public_ip
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_bundle_install" "nomad" {
  for_each = aws_instance.nomad_instance

  destination = var.nomad_install_dir
  release     = var.nomad_release == null ? var.nomad_release : merge(var.nomad_release, { product = "nomad" })
  artifactory = var.nomad_artifactory_release
  path        = var.nomad_local_artifact_path

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = each.value.public_ip
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_consul_start" "consul" {
  for_each = enos_bundle_install.consul

  bin_path = local.consul_bin_path
  data_dir = var.consul_data_dir
  config = {
    data_dir         = var.consul_data_dir
    datacenter       = "dc1"
    retry_join       = ["provider=aws tag_key=Type tag_value=${var.nomad_cluster_tag}"]
    server           = true
    bootstrap_expect = 3
    log_level        = "INFO"
    log_file         = var.consul_log_dir
  }
  unit_name = "consul"
  username  = "consul"

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = aws_instance.nomad_instance[each.key].public_ip
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_file" "nomad_service" {
  for_each = aws_instance.nomad_instance

  source      = abspath("${path.module}/configs/nomad.service")
  destination = "/etc/systemd/system/nomad.service"

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = aws_instance.nomad_instance[each.key].public_ip
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_file" "nomad_common_config" {
  for_each    = aws_instance.nomad_instance
  source      = abspath("${path.module}/configs/nomad.hcl")
  destination = "/etc/nomad.d/nomad.hcl"

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = aws_instance.nomad_instance[each.key].public_ip
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_file" "nomad_server_config" {
  for_each = aws_instance.nomad_instance

  source      = abspath("${path.module}/configs/server.hcl")
  destination = "/etc/nomad.d/server.hcl"

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = aws_instance.nomad_instance[each.key].public_ip
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_file" "nomad_client_config" {
  for_each = aws_instance.nomad_instance

  source      = abspath("${path.module}/configs/client.hcl")
  destination = "/etc/nomad.d/client.hcl"

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = aws_instance.nomad_instance[each.key].public_ip
      private_key_path = var.private_key_path
    }
  }
}


resource "enos_remote_exec" "install_docker" {
  # This uses apt so we need to block until deps are done
  depends_on = [
    enos_remote_exec.install_dependencies
  ]
  for_each = aws_instance.nomad_instance

  scripts = [abspath("${path.module}/../../templates/install-docker.sh")]
  environment = {
    INSTANCE_COUNT = var.instance_count
  }

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = aws_instance.nomad_instance[each.key].public_ip
      private_key_path = var.private_key_path
    }
  }
}

resource "enos_remote_exec" "start_nomad" {
  for_each = aws_instance.nomad_instance

  scripts = [abspath("${path.module}/../../templates/provision-nomad.sh")]
  environment = {
    INSTANCE_COUNT = var.instance_count
  }

  transport = {
    ssh = {
      user             = "ubuntu"
      host             = aws_instance.nomad_instance[each.key].public_ip
      private_key_path = var.private_key_path
    }
  }

  depends_on = [
    enos_consul_start.consul,
    enos_bundle_install.nomad,
    enos_file.nomad_service,
    enos_file.nomad_common_config,
    enos_file.nomad_server_config,
    enos_remote_exec.install_docker
  ]
}
