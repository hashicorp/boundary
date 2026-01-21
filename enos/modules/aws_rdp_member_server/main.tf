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
  domain_tld   = local.domain_parts[1] # top-level domain (example.com --> com)
}

resource "aws_instance" "member_server" {
  ami                    = data.aws_ami.infra.id
  instance_type          = var.instance_type
  vpc_security_group_ids = var.domain_controller_sec_group_id_list
  key_name               = var.domain_controller_aws_keypair_name
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
                  # Note: Windows Server 2016 does not support OpenSSH
                  %{if var.server_version != "2016"~}
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
                  %{endif~}

                  # Open firewall ports for RDP functionality
                  New-NetFirewallRule -Name kerberostcp -DisplayName 'Kerberos TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 88
                  New-NetFirewallRule -Name kerberosudp -DisplayName 'Kerberos UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 88
                  New-NetFirewallRule -Name rpctcp -DisplayName 'RPC TCP ' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 135
                  New-NetFirewallRule -Name rpcudp -DisplayName 'RPC UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 135
                  New-NetFirewallRule -Name ldaptcp -DisplayName 'LDAP TCP ' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 389
                  New-NetFirewallRule -Name ldapudp -DisplayName 'LDAP UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 389
                  New-NetFirewallRule -Name smbtcp -DisplayName 'SMB TCP ' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
                  New-NetFirewallRule -Name rdptcp -DisplayName 'RDP TCP ' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 3389
                  New-NetFirewallRule -Name rdpudp -DisplayName 'RDP UDP' -Enabled True -Direction Inbound -Protocol UDP -Action Allow -LocalPort 3389

                  # Adds member server to the domain
                  [int]$intix = Get-NetAdapter | % { Process { If ( $_.Status -eq "up" ) { $_.ifIndex } }}
                  Set-DNSClientServerAddress -interfaceIndex $intix -ServerAddresses ("${var.domain_controller_ip}","127.0.0.1")
                  $here_string_password = @'
${var.domain_admin_password}
'@
                  $password = ConvertTo-SecureString $here_string_password -AsPlainText -Force
                  $username = "${local.domain_sld}\Administrator"
                  $credential = New-Object System.Management.Automation.PSCredential($username,$password)

                  # check that domain can be reached
                  $timeout = 300
                  $interval = 10
                  $elapsed = 0

                  # check that domain can be reached
                  do {
                    try {
                      Resolve-DnsName -Name "${var.active_directory_domain}" -Server "${var.domain_controller_ip}" -ErrorAction Stop
                      Write-Host "resolved domain successfully."
                      break
                    } catch {
                        Write-Host "Could not resolve domain. Retrying in $interval seconds..."
                        Start-Sleep -Seconds $interval
                        $elapsed += $interval
                    }
                    if ($elapsed -ge $timeout) {
                      Write-Host "Resovling domain after 5 minutes. Exiting."
                      exit 1
                    }
                  } while ($true)

                  #logging to troubleshoot domain issues
                  Resolve-DnsName -Name "${var.active_directory_domain}" -Server "${var.domain_controller_ip}" -ErrorAction SilentlyContinue
                  Get-Service -Name LanmanWorkstation, Netlogon, RpcSs | Select-Object Name, DisplayName, Status

                  # Add computer to domain
                  $elapsed = 0
                  do {
                    try {
                      Add-Computer -DomainName "${var.active_directory_domain}" -Credential $credential
                      $result = (Get-WmiObject Win32_ComputerSystem).Domain
                      if ($result -ne "WORKGROUP") {
                        Write-Host "Added to domain successfully."
                        break
                      }
                    } catch {
                      Write-Host "Could not add to domain. Retrying in $interval seconds..."
                      Start-Sleep -Seconds $interval
                      $elapsed += $interval
                    }
                    if ($elapsed -ge $timeout) {
                      Write-Host "Adding to domain after 5 minutes. Exiting."
                      exit 1
                    }
                  } while ($true)
                  # Logging to determine domain and ssh state for debugging
                  (Get-WmiObject Win32_ComputerSystem).Domain
                  Get-Process -Name *ssh* -ErrorAction SilentlyContinue

                  # Enable Kerberos only authentication if required
                  %{if var.kerberos_only~}
                    Set-ItemProperty  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"  -Name RestrictSendingNTLMTraffic -Value 2
                    Set-ItemProperty  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"  -Name RestrictReceivingNTLMTraffic -Value 2
                  %{endif~}

                  # Enable audio
                  Set-Service -Name "Audiosrv" -StartupType Automatic
                  Start-Service -Name "Audiosrv"
                  Restart-Computer -Force
                </powershell>
              EOF

  metadata_options {
    http_endpoint          = "enabled"
    http_tokens            = "required"
    instance_metadata_tags = "enabled"
  }
  get_password_data = true

  tags = {
    Name = "${var.prefix}-rdp-member-server-${local.username}"
  }
}

locals {
  private_key = abspath(var.domain_controller_private_key)
}

resource "time_sleep" "wait_5_minutes" {
  depends_on      = [aws_instance.member_server]
  create_duration = "5m"
}

# wait for the SSH service to be available on the instance. We specifically use
# BatchMode=Yes to prevent SSH from prompting for a password to ensure that we
# can just SSH using the private key
resource "enos_local_exec" "wait_for_ssh" {
  count      = var.server_version != "2016" ? 1 : 0
  depends_on = [time_sleep.wait_5_minutes]
  inline     = ["timeout 600s bash -c 'until ssh -i ${local.private_key} -o BatchMode=Yes -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.member_server.public_ip} \"echo ready\"; do sleep 10; done'"]
}

# Retrieve the domain hostname of the member server, which will be used in
# Kerberos
resource "enos_local_exec" "get_hostname" {
  count = var.server_version != "2016" ? 1 : 0
  depends_on = [
    enos_local_exec.wait_for_ssh,
  ]

  inline = ["ssh -i ${local.private_key} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.member_server.public_ip} '$env:COMPUTERNAME'"]
}
