# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_version = ">= 1.1.2"

  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

data "enos_environment" "current" {}

data "aws_caller_identity" "current" {}

data "aws_ami" "infra" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-${var.server_version}-English-Full-Base*"]
  }
}

data "aws_vpc" "infra" {
  id = var.vpc_id
}

data "aws_subnets" "infra" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }
}

locals {
  username = split(":", data.aws_caller_identity.current.user_id)[1]
}

// We need a keypair to obtain the local administrator credentials to an AWS Windows based EC2 instance. So we generate it locally here
resource "tls_private_key" "rsa_4096_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

// Create an AWS keypair using the keypair we just generated
resource "aws_key_pair" "rdp-key" {
  key_name   = "${var.prefix}-${var.aws_key_pair_name}-${local.username}-${var.vpc_id}"
  public_key = tls_private_key.rsa_4096_key.public_key_openssh
}

// Create an AWS security group to allow RDP traffic in and out to from IP's on the allowlist.
resource "aws_security_group" "rdp_ingress" {
  name   = "${var.prefix}-rdp-ingress-${local.username}-${var.vpc_id}"
  vpc_id = var.vpc_id

  # Allow SSH traffic
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
  }

  # Allow traffic to DNS
  ingress {
    from_port = 53
    to_port   = 53
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)]
    ])
  }

  ingress {
    from_port = 53
    to_port   = 53
    protocol  = "udp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)]
    ])
  }


  # Allow traffic to Kerberos KDC
  ingress {
    from_port = 88
    to_port   = 88
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)]
    ])
  }

  ingress {
    from_port = 88
    to_port   = 88
    protocol  = "udp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)]
    ])
  }

  # Allow RPC traffic
  ingress {
    from_port = 135
    to_port   = 135
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)]
    ])
  }

  ingress {
    from_port = 135
    to_port   = 135
    protocol  = "udp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)]
    ])
  }

  # Allow LDAP traffic
  ingress {
    from_port = 389
    to_port   = 389
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)]
    ])
  }

  ingress {
    from_port = 389
    to_port   = 389
    protocol  = "udp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)]
    ])
  }

  # Allow RDP traffic
  ingress {
    from_port = 3389
    to_port   = 3389
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
    ])
  }

  ingress {
    from_port = 3389
    to_port   = 3389
    protocol  = "udp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
    ])
  }
}

// Create an AWS security group to allow all traffic originating from the default vpc
resource "aws_security_group" "allow_all_internal" {
  name   = "${var.prefix}-allow-all-internal-${local.username}-${var.vpc_id}"
  vpc_id = var.vpc_id

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

// Create a random string to be used in the user_data script
resource "random_string" "DSRMPassword" {
  length           = 8
  override_special = "." # I've set this explicitly so as to avoid characters such as "$" and "'" being used and requiring unneccesary complexity to our user_data scripts
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
}

// Deploy a Windows EC2 instance using the previously created, aws_security_group's, aws_key_pair and use a userdata script to create a set up Active Directory
resource "aws_instance" "domain_controller" {
  ami                    = data.aws_ami.infra.id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.rdp_ingress.id, aws_security_group.allow_all_internal.id]
  key_name               = aws_key_pair.rdp-key.key_name
  subnet_id              = data.aws_subnets.infra.ids[0]
  ipv6_address_count     = 1

  root_block_device {
    volume_type           = "gp2"
    volume_size           = var.root_block_device_size
    delete_on_termination = "true"
    encrypted             = true
  }


  user_data_replace_on_change = true

  user_data = <<EOF
                <powershell>
                  $password = ConvertTo-SecureString ${random_string.DSRMPassword.result} -AsPlainText -Force
                  Add-WindowsFeature -name ad-domain-services -IncludeManagementTools

                  # causes the instance to reboot
                  Install-ADDSForest -CreateDnsDelegation:$false -DomainMode Win2012R2 -DomainName ${var.active_directory_domain} -DomainNetbiosName ${var.active_directory_netbios_name} -ForestMode Win2012R2 -InstallDns:$true -SafeModeAdministratorPassword $password -Force:$true
                </powershell>
              EOF

  metadata_options {
    http_endpoint          = "enabled"
    instance_metadata_tags = "enabled"
  }
  get_password_data = true

  tags = {
    Name = "${var.prefix}-domain-controller-${local.username}"
  }
}

locals {
  password = rsadecrypt(aws_instance.domain_controller.password_data, tls_private_key.rsa_4096_key.private_key_pem)
}

resource "local_sensitive_file" "private_key" {
  depends_on = [tls_private_key.rsa_4096_key]

  content         = tls_private_key.rsa_4096_key.private_key_pem
  filename        = "${path.root}/.terraform/tmp/key-domain-controller-${timestamp()}"
  file_permission = "0400"
}

resource "time_sleep" "wait_10_minutes" {
  depends_on      = [aws_instance.domain_controller]
  create_duration = "10m"
}
