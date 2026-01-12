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

locals {
  client_to_server_version = {
    "win10" = "2022"
    "win11" = "2025"
  }
}

data "enos_environment" "current" {}

data "aws_caller_identity" "current" {}

data "aws_ami" "infra" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-${local.client_to_server_version[var.client_version]}-English-Full-Base*"]
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
resource "tls_private_key" "rsa-4096-key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

// Create an AWS keypair using the keypair we just generated
resource "aws_key_pair" "rdp-key" {
  key_name   = "${var.prefix}-windows-client-${local.username}-${var.vpc_id}"
  public_key = tls_private_key.rsa-4096-key.public_key_openssh
}

// Create an AWS security group to allow SSH
resource "aws_security_group" "windows_client" {
  name   = "${var.prefix}-windows-client-${local.username}-${var.vpc_id}"
  vpc_id = var.vpc_id

  # Allow SSH from the public IP of the user
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
    ])
  }

  # Allow RDP from the public IP of the user. This is useful for manual testing
  ingress {
    from_port = 3389
    to_port   = 3389
    protocol  = "tcp"
    cidr_blocks = flatten([
      formatlist("%s/32", data.enos_environment.current.public_ipv4_addresses),
      join(",", data.aws_vpc.infra.cidr_block_associations.*.cidr_block),
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
  }

  // Allow all traffic originating from the VPC
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    cidr_blocks = [data.aws_vpc.infra.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
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
  test_username = "autologinuser"
  test_password = random_string.DSRMPassword.result
}

// Deploy a Windows EC2 instance
resource "aws_instance" "client" {
  ami                    = data.aws_ami.infra.id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.windows_client.id]
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
                  # set variables for retry loops
                  $timeout = 300
                  $interval = 30

                  # Set up SSH so we can remotely manage the instance
                  ## Install OpenSSH Server and Client
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

                  ## Set PowerShell as the default SSH shell
                  New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value (Get-Command powershell.exe).Path -PropertyType String -Force

                  ## Configure SSH server to use private key authentication so that scripts don't have to use passwords
                  ## Save the private key from instance metadata
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

                  ## Ensure the SSH agent pulls in the new key.
                  Set-Service -Name ssh-agent -StartupType "Automatic"
                  Restart-Service -Name ssh-agent
                  Restart-Service -Name sshd

                  ## Open the firewall for SSH connections
                  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

                  # Create a non-admin user to be used for RDP connection. This
                  # is needed since the scheduled task that runs desktop automation
                  # doesn't work in an Administrator context.
                  ## Create a local user
                  $Username = "${local.test_username}"
                  $Password = ConvertTo-SecureString "${local.test_password}" -AsPlainText -Force
                  New-LocalUser $Username -Password $Password -FullName "Auto Login User" -Description "User for Auto Login"
                  Add-LocalGroupMember -Group "Administrators" -Member $Username

                  # Disable windows snapping assist. This is done to reduce
                  # complexity in RDP automated tests since the snapping assist
                  # window introduces an additional UI element that needs to be handled.
                  Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "SnapAssist" -Value 0 -Force

                  $script = 'Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SnapAssist" -Value 0 -Force; Stop-Process -Name explorer -Force; Start-Process explorer.exe'
                  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonInteractive -WindowStyle Hidden -Command $script"
                  $trigger = New-ScheduledTaskTrigger -AtLogOn -User "autologinuser"
                  Register-ScheduledTask -TaskName "RemoveSnapAssist" -Action $action -Trigger $trigger -User "autologinuser" -RunLevel Highest -Force

                  # Set registry keys for auto-login
                  $regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
                  Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1" -Type String
                  Set-ItemProperty -Path $regPath -Name "DefaultUsername" -Value $Username -Type String
                  Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value "${local.test_password}" -Type String
                  Set-ItemProperty -Path $regPath -Name "DefaultDomainName" -Value "$env:COMPUTERNAME" -Type String

                  # Enable audio
                  Set-Service -Name "Audiosrv" -StartupType Automatic
                  Start-Service -Name "Audiosrv"
                </powershell>
              EOF

  metadata_options {
    http_endpoint          = "enabled"
    http_tokens            = "required"
    instance_metadata_tags = "enabled"
  }
  get_password_data = true

  tags = {
    Name = "${var.prefix}-windows-client-${local.username}"
  }
}

locals {
  boundary_cli_zip_path = var.boundary_cli_zip_path != "" ? abspath(var.boundary_cli_zip_path) : ""
  test_dir              = "C:/Test/" # needs to end in a / to ensure it creates the directory
}

resource "local_sensitive_file" "private_key" {
  depends_on = [tls_private_key.rsa-4096-key]

  content         = tls_private_key.rsa-4096-key.private_key_pem
  filename        = "${path.root}/.terraform/tmp/key-client-${timestamp()}"
  file_permission = "0400"
}

# wait for the SSH service to be available on the instance. We specifically use
# BatchMode=Yes to prevent SSH from prompting for a password to ensure that we
# can just SSH using the private key
resource "enos_local_exec" "wait_for_ssh" {
  depends_on = [aws_instance.client]
  inline     = ["timeout 600s bash -c 'until ssh -i ${abspath(local_sensitive_file.private_key.filename)} -o BatchMode=Yes -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.client.public_ip} \"echo ready\"; do sleep 10; done'"]
}

resource "enos_local_exec" "get_go_version" {
  inline = ["cat $(echo $(git rev-parse --show-toplevel))/.go-version | xargs"]
}

resource "enos_local_exec" "make_dir" {
  count = var.boundary_cli_zip_path != "" ? 1 : 0
  depends_on = [
    enos_local_exec.wait_for_ssh,
  ]

  inline = ["ssh -i ${abspath(local_sensitive_file.private_key.filename)} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.client.public_ip} mkdir -Force ${local.test_dir}"]
}

# copy the boundary cli zip file onto the windows client
resource "enos_local_exec" "add_boundary_cli" {
  count = var.boundary_cli_zip_path != "" ? 1 : 0
  depends_on = [
    local_sensitive_file.private_key,
    enos_local_exec.make_dir,
  ]

  inline = ["scp -i ${abspath(local_sensitive_file.private_key.filename)} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${local.boundary_cli_zip_path} Administrator@${aws_instance.client.public_ip}:${local.test_dir}"]
}

resource "archive_file" "boundary_src_zip" {
  count       = var.boundary_src_path != "" ? 1 : 0
  type        = "zip"
  source_dir  = var.boundary_src_path
  output_path = "${path.root}/.terraform/tmp/boundary-src.zip"
  excludes    = ["**/enos/**", "**/node_modules/**", "bin/**", "**/.git/**", "plugins/**/*.gz", "website/**", "**/ui/.tmp/**"]
}

resource "enos_local_exec" "add_boundary_src" {
  count = var.boundary_src_path != "" ? 1 : 0
  depends_on = [
    enos_local_exec.make_dir,
    archive_file.boundary_src_zip
  ]

  inline = ["scp -i ${abspath(local_sensitive_file.private_key.filename)} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${archive_file.boundary_src_zip[0].output_path} Administrator@${aws_instance.client.public_ip}:${local.test_dir}"]
}

# create a powershell script to unzip the boundary cli zip file and add it to
# the PATH
resource "local_file" "powershell_script" {
  count = var.boundary_cli_zip_path != "" ? 1 : 0
  depends_on = [
    archive_file.boundary_src_zip
  ]
  content = templatefile("${path.module}/scripts/setup.ps1", {
    boundary_cli_zip_path = "${local.test_dir}/${basename(local.boundary_cli_zip_path)}"
    boundary_src_zip_path = "${local.test_dir}/${basename(archive_file.boundary_src_zip[0].output_path)}"
    go_version            = "${enos_local_exec.get_go_version.stdout}"
    github_token          = "${var.github_token}"
    vault_version         = "${var.vault_version}"
  })
  filename = "${path.root}/.terraform/tmp/setup_windows_client.ps1"
}

# copy the powershell script onto the windows client
resource "enos_local_exec" "add_powershell_script" {
  count = var.boundary_cli_zip_path != "" ? 1 : 0
  depends_on = [
    enos_local_exec.add_boundary_cli,
    local_file.powershell_script,
  ]

  inline = ["scp -i ${abspath(local_sensitive_file.private_key.filename)} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${abspath(local_file.powershell_script[0].filename)} Administrator@${aws_instance.client.public_ip}:${local.test_dir}"]
}

# run the powershell script on the windows client
resource "enos_local_exec" "run_powershell_script" {
  count = var.boundary_cli_zip_path != "" ? 1 : 0
  depends_on = [
    enos_local_exec.add_boundary_cli,
    enos_local_exec.add_powershell_script,
    enos_local_exec.wait_for_ssh,
  ]

  # running this script as test_username so that go modules will be set up for
  # the user used for RDP tests
  inline = ["ssh -i ${abspath(local_sensitive_file.private_key.filename)} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ${local.test_username}@${aws_instance.client.public_ip} ${local.test_dir}/${basename(local_file.powershell_script[0].filename)}"]
}

# used for debug
resource "local_file" "powershell_script_output" {
  depends_on = [enos_local_exec.run_powershell_script]
  count      = var.boundary_cli_zip_path != "" ? 1 : 0
  content    = enos_local_exec.run_powershell_script[0].stdout
  filename   = "${path.root}/.terraform/tmp/setup_windows_client.out"
}
