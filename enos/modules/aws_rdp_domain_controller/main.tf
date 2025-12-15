# Copyright IBM Corp. 2020, 2025
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
    ])
  }

  # Allow LDAPS (Lightweight Directory Access Protocol Secure) traffic to query Active Directory
  ingress {
    from_port = 636
    to_port   = 636
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
    ])
  }

  ingress {
    from_port = 636
    to_port   = 636
    protocol  = "udp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
      data.aws_vpc.infra.ipv6_cidr_block
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
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
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : flatten([
      [for ip in coalesce(data.enos_environment.current.public_ipv6_addresses, []) : cidrsubnet("${ip}/64", 0, 0)],
    ])
  }
}

// Create an AWS security group to allow all traffic originating from the default vpc
resource "aws_security_group" "allow_all_internal" {
  name   = "${var.prefix}-allow-all-internal-${local.username}-${var.vpc_id}"
  vpc_id = var.vpc_id

  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    self             = true
    cidr_blocks      = [data.aws_vpc.infra.cidr_block]
    ipv6_cidr_blocks = var.ip_version == "4" ? [] : [data.aws_vpc.infra.ipv6_cidr_block]
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
  ipv6_address_count     = var.ip_version == "6" || var.ip_version == "dual" ? 1 : 0

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

                  # Set up SSH so we can remotely manage the instance
                  # This is set up slightly different on the domain controller
                  # due to issues when setting up SSH and creating a domain in
                  # the same user_data script. Now, SSH is set up as a scheduled
                  # task that will execute on next boot
                  # Note: Windows Server 2016 does not support OpenSSH
                  %{if var.server_version != "2016"~}
                  $sshSetupScript = @'
  # Wait for network to be available
  $networkTimeout = 120
  $networkElapsed = 0
  do {
    $network = Test-NetConnection -ComputerName "169.254.169.254" -Port 80 -WarningAction SilentlyContinue
    if ($network.TcpTestSucceeded) {
      Write-Host "Network is available"
      break
    }
    Write-Host "Waiting for network..."
    Start-Sleep -Seconds 10
    $networkElapsed += 10
  } while ($networkElapsed -lt $networkTimeout)

  if ($networkElapsed -ge $networkTimeout) {
    Write-Host "Network not available after timeout. Exiting."
    exit 1
  }

  # set variables for retry loops
  $timeout = 300
  $interval = 30
  # Install OpenSSH Server and Client
  # Loop to make sure that SSH installs correctly
  $elapsed = 0
  do {
    try {
      Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
      Set-Service -Name sshd -StartupType 'Automatic'
      Start-Service sshd
      $result = Get-Process -Name "sshd" -ErrorAction SilentlyContinue
      if ($result) {
        Write-Host "Successfully added and started openSSH server"
        break
      }
    } catch {
        Write-Host "SSH server was not installed, retrying"
        Start-Sleep -Seconds $interval
        $elapsed += $interval
    }
    if ($elapsed -ge $timeout) {
        Write-Host "SSH server installation failed after 5 minutes. Exiting."
        exit 1
    }
  } while ($true)
  $elapsed = 0
  do {
    try {
      Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
      Set-Service -Name ssh-agent -StartupType Automatic
      Start-Service ssh-agent
      $result = Get-Process -Name "ssh-agent" -ErrorAction SilentlyContinue
      if ($result) {
          Write-Host "Successfully added and started openSSH agent"
          break
      }
    } catch {
        Write-Host "SSH server was not installed, retrying"
        Start-Sleep -Seconds $interval
        $elapsed += $interval
    }
    if ($elapsed -ge $timeout) {
        Write-Host "SSH server installation failed after 5 minutes. Exiting."
        exit 1
    }
  } while ($true)
  # Set PowerShell as the default SSH shell
  New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value (Get-Command powershell.exe).Path -PropertyType String -Force
  # Configure SSH server to use private key authentication so that scripts don't have to use passwords
  # Save the private key from instance metadata
  $ImdsToken = (Invoke-WebRequest -Uri 'http://169.254.169.254/latest/api/token' -Method 'PUT' -Headers @{'X-aws-ec2-metadata-token-ttl-seconds' = 2160} -UseBasicParsing).Content
  $ImdsHeaders = @{'X-aws-ec2-metadata-token' = $ImdsToken}
  $AuthorizedKey = (Invoke-WebRequest -Uri 'http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key' -Headers $ImdsHeaders -UseBasicParsing).Content
  $AuthorizedKeysPath = 'C:\ProgramData\ssh\administrators_authorized_keys'
  New-Item -Path $AuthorizedKeysPath -ItemType File -Value $AuthorizedKey -Force
  # Set the correct permissions on the authorized_keys file
  icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r
  icacls "C:\ProgramData\ssh\administrators_authorized_keys" /grant "Administrators:F" /grant "SYSTEM:F"
  icacls "C:\ProgramData\ssh\administrators_authorized_keys" /remove "Users"
  icacls "C:\ProgramData\ssh\administrators_authorized_keys" /remove "Authenticated Users"
  # Ensure the SSH agent pulls in the new key.
  Set-Service -Name ssh-agent -StartupType "Automatic"
  Restart-Service -Name ssh-agent
  Restart-Service -Name sshd
  # Open the firewall for SSH connections
  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
'@
                  Set-Content -Path "C:\ssh-setup.ps1" -Value $sshSetupScript

                  # Register a scheduled task to run the SSH setup script at next boot
                  $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\ssh-setup.ps1"
                  $Trigger = New-ScheduledTaskTrigger -AtStartup
                  $Trigger.Delay = 'PT2M'  # Wait 2 minutes after startup to allow networking services to load
                  $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                  Register-ScheduledTask -TaskName "SetupOpenSSH" -Action $Action -Trigger $Trigger -Principal $Principal;
                  %{endif~}

                  # Open firewall ports for RDP functionality
                  New-NetFirewallRule -Name kerberostcp -DisplayName 'Kerberos TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 88
                  New-NetFirewallRule -Name kerberosudp -DisplayName 'Kerberos UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 88
                  New-NetFirewallRule -Name rpctcp -DisplayName 'RPC TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 135
                  New-NetFirewallRule -Name rpcudp -DisplayName 'RPC UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 135
                  New-NetFirewallRule -Name ldaptcp -DisplayName 'LDAP TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 389
                  New-NetFirewallRule -Name ldapudp -DisplayName 'LDAP UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 389
                  New-NetFirewallRule -Name smbtcp -DisplayName 'SMB TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
                  New-NetFirewallRule -Name ldapstcp -DisplayName 'LDAPS TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 636
                  New-NetFirewallRule -Name ldapsudp -DisplayName 'LDAPS UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 636
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
  tags = {
    Name = "${var.prefix}-domain-controller-${local.username}"
  }
}

resource "local_sensitive_file" "private_key" {
  depends_on = [tls_private_key.rsa_4096_key]

  content         = tls_private_key.rsa_4096_key.private_key_pem
  filename        = "${path.root}/.terraform/tmp/key-domain-controller-${timestamp()}"
  file_permission = "0400"
}

resource "time_sleep" "wait_for_reboot" {
  depends_on      = [aws_instance.domain_controller]
  create_duration = "20m"
}

data "aws_instance" "instance_password" {
  depends_on        = [time_sleep.wait_10_minutes]
  instance_id       = aws_instance.domain_controller.id
  get_password_data = true
}

# wait for the SSH service to be available on the instance. We specifically use
# BatchMode=Yes to prevent SSH from prompting for a password to ensure that we
# can just SSH using the private key
resource "enos_local_exec" "wait_for_ssh" {
  depends_on = [time_sleep.wait_for_reboot]
  count      = var.server_version != "2016" ? 1 : 0
  inline     = ["timeout 600s bash -c 'until ssh -i ${abspath(local_sensitive_file.private_key.filename)} -o BatchMode=Yes -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.domain_controller.public_ip} \"echo ready\"; do sleep 10; done'"]
}

locals {
  test_dir        = "C:/Test"
  vault_ldap_user = "VaultLDAP"
}

resource "enos_local_exec" "make_dir" {
  depends_on = [
    enos_local_exec.wait_for_ssh,
  ]

  count  = var.server_version != "2016" ? 1 : 0
  inline = ["ssh -i ${abspath(local_sensitive_file.private_key.filename)} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.domain_controller.public_ip} mkdir -Force ${local.test_dir}"]
}

resource "local_file" "ldaps_script" {
  depends_on = [
    enos_local_exec.make_dir,
  ]
  count = var.server_version != "2016" ? 1 : 0
  content = templatefile("${path.module}/scripts/setup_ldaps.ps1", {
    active_directory_domain = var.active_directory_domain
    vault_ldap_user         = local.vault_ldap_user
  })
  filename = "${path.root}/.terraform/tmp/setup_ldaps.ps1"
}

resource "enos_local_exec" "add_ldaps_script" {
  depends_on = [
    local_file.ldaps_script,
  ]

  count  = var.server_version != "2016" ? 1 : 0
  inline = ["scp -i ${abspath(local_sensitive_file.private_key.filename)} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${abspath(local_file.ldaps_script[0].filename)} Administrator@${aws_instance.domain_controller.public_ip}:${local.test_dir}"]
}

resource "enos_local_exec" "run_ldaps_script" {
  depends_on = [
    enos_local_exec.add_ldaps_script,
  ]

  count  = var.server_version != "2016" ? 1 : 0
  inline = ["ssh -i ${abspath(local_sensitive_file.private_key.filename)} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.domain_controller.public_ip} ${local.test_dir}/${basename(local_file.ldaps_script[0].filename)}"]
}

resource "local_file" "ldaps_script_output" {
  depends_on = [enos_local_exec.run_ldaps_script]
  count      = var.server_version != "2016" ? 1 : 0
  content    = enos_local_exec.run_ldaps_script[0].stdout
  filename   = "${path.root}/.terraform/tmp/setup_ldaps.out"
}
