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
  username     = split(":", data.aws_caller_identity.current.user_id)[1]
  domain_parts = split(".", var.active_directory_domain)
  domain_sld   = local.domain_parts[0] # second-level domain (example.com --> example)
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

  # Allow DNS (Domain Name System) traffic to resolve hostnames
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

  # Allow Kerberos authentication traffic
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

  # Allow RPC (Remote Procedure Calls) traffic
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

  # Allow LDAP (Lightweight Directory Access Protocol) traffic to query Active Directory
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

  # Allow Server Message Block (SMB) traffic
  ingress {
    from_port = 445
    to_port   = 445
    protocol  = "tcp"
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
                  # Configure the server to use reliable external NTP sources and mark itself as reliable
                  # We use pool.ntp.org, a public cluster of time servers. 0x9 flag means Client + SpecialInterval.
                  w32tm /config /manualpeerlist:"pool.ntp.org,0x9" /syncfromflags:manual /reliable:yes /update
                  # Restart the Windows Time service to apply the new configuration
                  Stop-Service w32time
                  Start-Service w32time
                  # Force an immediate time synchronization
                  w32tm /resync /force

                  # Open firewall ports for RDP functionality
                  New-NetFirewallRule -Name kerberostcp -DisplayName 'Kerberos TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 88
                  New-NetFirewallRule -Name kerberosudp -DisplayName 'Kerberos UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 88
                  New-NetFirewallRule -Name rpctcp -DisplayName 'RPC TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 135
                  New-NetFirewallRule -Name rpcudp -DisplayName 'RPC UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 135
                  New-NetFirewallRule -Name ldaptcp -DisplayName 'LDAP TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 389
                  New-NetFirewallRule -Name ldapudp -DisplayName 'LDAP UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 389
                  New-NetFirewallRule -Name smbtcp -DisplayName 'SMB TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
                  New-NetFirewallRule -Name rdptcp -DisplayName 'RDP TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 3389
                  New-NetFirewallRule -Name rdpudp -DisplayName 'RDP UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 3389

                  # Add computer to the domain and promote to a domain
                  # controller
                  Add-WindowsFeature -name ad-domain-services -IncludeManagementTools
                  $password = ConvertTo-SecureString ${random_string.DSRMPassword.result} -AsPlainText -Force
                  # causes the instance to reboot
                  Install-ADDSForest -CreateDnsDelegation:$false -DomainMode 7 -DomainName ${var.active_directory_domain} -DomainNetbiosName ${local.domain_sld} -ForestMode 7 -InstallDns:$true -NoRebootOnCompletion:$false -SafeModeAdministratorPassword $password -Force:$true
                </powershell>
              EOF

  metadata_options {
    http_endpoint          = "enabled"
    http_tokens            = "required"
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
