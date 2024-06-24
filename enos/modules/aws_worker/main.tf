# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

data "enos_environment" "current" {}

locals {
  selected_az = data.aws_availability_zones.available.names[random_integer.az.result]
  common_tags = merge(
    var.common_tags,
    {
      Type   = var.cluster_tag
      Module = "boundary-worker"
      Pet    = random_pet.worker.id
    },
  )
}

resource "random_pet" "worker" {
  separator = "_"
}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "zone-name"
    values = var.availability_zones
  }
}

data "aws_availability_zone" "worker_az" {
  name = local.selected_az
}

data "aws_kms_key" "kms_key" {
  key_id = var.kms_key_arn
}

resource "random_integer" "az" {
  min = 0
  max = length(data.aws_availability_zones.available.names) - 1
  keepers = {
    # Generate a new integer each time the list of aws_availability_zones changes
    # keepers have to be strings, sort the list in case order changes but zones don't
    listener_arn = join("", sort(data.aws_availability_zones.available.names))
  }
}

# Create a subnet so that the worker doesn't share one with a controller
resource "aws_subnet" "default" {
  vpc_id                  = var.vpc_id
  cidr_block              = "10.13.9.0/24"
  map_public_ip_on_launch = true
  availability_zone       = local.selected_az
  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.vpc_id}_worker_${random_pet.worker.id}_subnet"
    },
  )
}

# The worker instance is a part of this security group, not to be confused with the next rule below
resource "aws_security_group" "default" {
  name        = "boundary-sg-worker-${random_pet.worker.id}"
  description = "SSH to worker to KMS and controllers"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH to the worker instance"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = flatten([formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses)])
  }

  ingress {
    description = "Communication from Boundary controller to worker"
    from_port   = 9202
    to_port     = 9202
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    local.common_tags,
    {
      "Name" = "${var.vpc_id}_worker_sg"
    },
  )
}

# This module only manages a rule for the controller SG that is vital to the worker's operation
# This module does _not_ manage the security group itself
resource "aws_vpc_security_group_ingress_rule" "worker_to_controller" {
  description       = "This rule allows traffic from a worker to controllers over WAN"
  security_group_id = var.controller_sg_id
  cidr_ipv4         = "${aws_instance.worker.public_ip}/32"
  from_port         = 9201
  to_port           = 9201
  ip_protocol       = "tcp"
}

data "aws_vpc" "vpc" {
  id = var.vpc_id
}

resource "aws_route_table_association" "worker_rta" {
  subnet_id      = aws_subnet.default.id
  route_table_id = data.aws_vpc.vpc.main_route_table_id
}

resource "aws_instance" "worker" {
  ami                    = var.ubuntu_ami_id
  instance_type          = var.worker_instance_type
  vpc_security_group_ids = [aws_security_group.default.id]
  subnet_id              = aws_subnet.default.id
  key_name               = var.ssh_aws_keypair
  iam_instance_profile   = aws_iam_instance_profile.boundary_profile.name
  monitoring             = var.worker_monitoring

  root_block_device {
    iops        = var.ebs_iops
    volume_size = var.ebs_size
    volume_type = var.ebs_type
    throughput  = var.ebs_throughput
    tags        = local.common_tags
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${var.name_prefix}-boundary-worker",
    },
  )
}

resource "enos_bundle_install" "worker" {
  depends_on = [aws_instance.worker, aws_route_table_association.worker_rta]

  destination = var.boundary_install_dir
  artifactory = var.boundary_artifactory_release
  path        = var.local_artifact_path
  release     = var.boundary_release == null ? var.boundary_release : merge(var.boundary_release, { product = "boundary", edition = "oss" })

  transport = {
    ssh = {
      host = aws_instance.worker.public_ip
    }
  }
}

resource "enos_remote_exec" "update_path_worker" {
  depends_on = [enos_bundle_install.worker]

  environment = {
    BOUNDARY_INSTALL_DIR = var.boundary_install_dir
  }

  scripts = [abspath("${path.module}/scripts/set-up-login-shell-profile.sh")]

  transport = {
    ssh = {
      host = aws_instance.worker.public_ip
    }
  }
}

resource "enos_file" "worker_config" {
  depends_on = [enos_bundle_install.worker]

  destination = "/etc/boundary/boundary.hcl"
  content = templatefile("${path.module}/${var.config_file_path}", {
    id                     = random_pet.worker.id
    kms_key_id             = data.aws_kms_key.kms_key.id
    public_addr            = aws_instance.worker.public_ip
    type                   = jsonencode(var.worker_type_tags)
    region                 = data.aws_availability_zone.worker_az.region
    controller_addresses   = jsonencode(var.controller_addresses)
    recording_storage_path = var.recording_storage_path
  })

  transport = {
    ssh = {
      host = aws_instance.worker.public_ip
    }
  }
}

resource "enos_boundary_start" "worker_start" {
  depends_on = [
    enos_file.worker_config,
    aws_vpc_security_group_ingress_rule.worker_to_controller,
  ]

  bin_path               = "/opt/boundary/bin"
  config_path            = "/etc/boundary"
  recording_storage_path = var.recording_storage_path != "" ? var.recording_storage_path : null
  transport = {
    ssh = {
      host = aws_instance.worker.public_ip
    }
  }
}

resource "random_string" "cluster_id" {
  length  = 8
  lower   = true
  upper   = false
  numeric = false
  special = false
}
