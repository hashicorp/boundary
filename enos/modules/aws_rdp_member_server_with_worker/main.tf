# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_version = ">= 1.1.2"

  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }

    tls = {
      source = "hashicorp/tls"
    }

    archive = {
      source = "hashicorp/archive"
    }
  }
}

data "enos_environment" "current" {}

data "aws_caller_identity" "current" {}

data "aws_kms_key" "kms_key" {
  key_id = var.kms_key_arn
}

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

resource "random_string" "DSRMPassword" {
  length           = 8
  override_special = "." # I've set this explicitly so as to avoid characters such as "$" and "'" being used and requiring unneccesary complexity to our user_data scripts
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
}

locals {
  domain_parts = split(".", var.active_directory_domain)
  domain_sld   = local.domain_parts[0] # second-level domain (example.com --> example)
  domain_tld   = local.domain_parts[1] # top-level domain (example.com --> com)
}

// Deploy a Windows EC2 instance
resource "aws_instance" "worker" {
  ami                    = data.aws_ami.infra.id
  instance_type          = var.instance_type
  vpc_security_group_ids = flatten([var.boundary_security_group, var.domain_controller_sec_group_id_list])
  key_name               = var.domain_controller_aws_keypair_name
  subnet_id              = data.aws_subnets.infra.ids[0]
  iam_instance_profile   = var.iam_name
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

                  # set variables for retry loops
                  $timeout = 300
                  $interval = 30

                  # Set up SSH so we can remotely manage the instance
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

                  # Open the firewall for SSH
                  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

                  # Open firewall for boundary connections
                  New-NetFirewallRule -Name boundary_in -DisplayName 'Boundary inbound' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 9202
                  New-NetFirewallRule -Name boundary_out -DisplayName 'Boundary outbound' -Enabled True -Direction Outbound -Protocol TCP -Action Allow -LocalPort 9202

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

                  # Add computer to the domain
                  [int]$intix = Get-NetAdapter | % { Process { If ( $_.Status -eq "up" ) { $_.ifIndex } }}
                  Set-DNSClientServerAddress -interfaceIndex $intix -ServerAddresses ("${var.domain_controller_ip}","127.0.0.1")
                  $here_string_password = @'
${var.domain_admin_password}
'@
                  $password = ConvertTo-SecureString $here_string_password -AsPlainText -Force
                  $username = "${local.domain_sld}\Administrator"
                  $credential = New-Object System.Management.Automation.PSCredential($username,$password)

                  # check that domain can be reached
                  $elapsed = 0
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
                      Write-Host "Resolving domain after 5 minutes. Exiting."
                      exit 1
                    }
                  } while ($true)

                  # Logging to troubleshoot domain issues
                  Resolve-DnsName -Name "${var.active_directory_domain}" -Server "${var.domain_controller_ip}" -ErrorAction SilentlyContinue
                  Get-Service -Name LanmanWorkstation, Netlogon, RpcSs | Select-Object Name, DisplayName, Status


                  $timeout = 900
                  $interval = 30
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
                </powershell>
              EOF

  metadata_options {
    http_endpoint          = "enabled"
    http_tokens            = "required"
    instance_metadata_tags = "enabled"
  }

  tags = {
    Name = "${var.prefix}-windows-worker-${local.username}"
  }
}

resource "time_sleep" "wait_for_worker_init" {
  depends_on = [aws_instance.worker]
  create_duration = "3m"
}

data "aws_instance" "instance_password" {
  depends_on  = [time_sleep.wait_for_worker_init]
  instance_id = aws_instance.worker.id
  get_password_data = true
}

locals {
  private_key           = abspath(var.domain_controller_private_key)
  boundary_cli_zip_path = var.boundary_cli_zip_path != "" ? abspath(var.boundary_cli_zip_path) : ""
  test_dir              = "C:/Test/" # needs to end in a / to ensure it creates the directory
}


resource "enos_local_exec" "wait_for_ssh" {
  depends_on = [
    aws_instance.worker,
  ]
  inline = ["timeout 600s bash -c 'until ssh -i ${local.private_key} -o BatchMode=Yes -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.worker.public_ip} \"echo ready\"; do sleep 10; done'"]
}

resource "enos_local_exec" "make_dir" {
  depends_on = [
    enos_local_exec.wait_for_ssh,
  ]

  inline = ["ssh -i ${local.private_key} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.worker.public_ip} mkdir -Force ${local.test_dir}"]
}

# copy the boundary cli zip file onto the windows client
resource "enos_local_exec" "add_boundary_cli" {
  depends_on = [
    enos_local_exec.make_dir,
  ]

  inline = ["scp -i ${local.private_key} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${local.boundary_cli_zip_path} Administrator@${aws_instance.worker.public_ip}:${local.test_dir}"]
}

# create a powershell script to unzip the boundary cli zip file and add it to
# the PATH
resource "local_file" "powershell_script" {
  depends_on = [
    enos_local_exec.add_boundary_cli
  ]
  content = templatefile("${path.module}/scripts/setup.ps1", {
    boundary_cli_zip_path = "${local.test_dir}/${basename(local.boundary_cli_zip_path)}"
    test_dir              = local.test_dir
  })
  filename = "${path.root}/.terraform/tmp/setup_worker.ps1"
}

# create a worker config file for boundary
resource "local_file" "worker_config" {
  depends_on = [
    enos_local_exec.add_boundary_cli,
  ]
  content = templatefile("${path.module}/${var.worker_config_file_path}", {
    controller_ip           = var.ip_version == "4" ? jsonencode(var.controller_ip) : jsonencode(formatlist("[%s]:9201", flatten(var.controller_ip)))
    aws_kms_key             = data.aws_kms_key.kms_key.id
    aws_region              = var.aws_region
    worker_public_ip        = aws_instance.worker.public_ip
    test_dir                = local.test_dir
    hcp_boundary_cluster_id = var.hcp_boundary_cluster_id
  })
  filename = "${path.root}/.terraform/tmp/worker.hcl"
}

# copy the powershell script onto the windows client
resource "enos_local_exec" "add_powershell_script" {
  depends_on = [
    enos_local_exec.add_boundary_cli,
    local_file.powershell_script,
  ]

  inline = ["scp -i ${local.private_key} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${abspath(local_file.powershell_script.filename)} Administrator@${aws_instance.worker.public_ip}:${local.test_dir}"]
}

# copy the worker config script onto the windows client
resource "enos_local_exec" "add_worker_config" {
  depends_on = [
    enos_local_exec.add_boundary_cli,
    local_file.worker_config,
  ]

  inline = ["scp -i ${local.private_key} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${abspath(local_file.worker_config.filename)} Administrator@${aws_instance.worker.public_ip}:${local.test_dir}"]
}


# run the powershell script on the windows client
resource "enos_local_exec" "run_powershell_script" {
  depends_on = [
    enos_local_exec.add_boundary_cli,
    enos_local_exec.add_powershell_script,
    enos_local_exec.wait_for_ssh,
    enos_local_exec.add_worker_config,
  ]

  inline = ["ssh -i ${local.private_key} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.worker.public_ip} ${local.test_dir}/${basename(local_file.powershell_script.filename)}"]
}

resource "time_sleep" "wait_2_minutes" {
  depends_on      = [enos_local_exec.run_powershell_script]
  create_duration = "2m"
}

# used for debug
resource "local_file" "powershell_script_output" {
  depends_on = [enos_local_exec.run_powershell_script]
  content    = enos_local_exec.run_powershell_script.stdout
  filename   = "${path.root}/.terraform/tmp/setup_worker.out"
}
