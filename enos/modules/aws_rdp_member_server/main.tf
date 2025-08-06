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
                  # Set up SSH so we can remotely manage the instance
                  ## Install OpenSSH Server and Client
                  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
                  Set-Service -Name sshd -StartupType 'Automatic'
                  Start-Service sshd

                  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
                  Set-Service -Name ssh-agent -StartupType Automatic
                  Start-Service ssh-agent

                  ## Set PowerShell as the default SSH shell
                  New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value (Get-Command powershell.exe).Path -PropertyType String -Force

                  ## Configure SSH server to use private key authentication so that scripts don't have to use passwords
                  ## Save the private key from instance metadata
                  $ImdsToken = (Invoke-WebRequest -Uri 'http://169.254.169.254/latest/api/token' -Method 'PUT' -Headers @{'X-aws-ec2-metadata-token-ttl-seconds' = 2160} -UseBasicParsing).Content
                  $ImdsHeaders = @{'X-aws-ec2-metadata-token' = $ImdsToken}
                  $AuthorizedKey = (Invoke-WebRequest -Uri 'http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key' -Headers $ImdsHeaders -UseBasicParsing).Content
                  $AuthorizedKeysPath = 'C:\ProgramData\ssh\administrators_authorized_keys'
                  New-Item -Path $AuthorizedKeysPath -ItemType File -Value $AuthorizedKey -Force

                  ## Ensure the SSH agent pulls in the new key.
                  Set-Service -Name ssh-agent -StartupType "Automatic"
                  Restart-Service -Name ssh-agent

                  ## Open the firewall for SSH connections
                  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

                  # Adds member server to the domain
                  [int]$intix = Get-NetAdapter | % { Process { If ( $_.Status -eq "up" ) { $_.ifIndex } }}
Set-DNSClientServerAddress -interfaceIndex $intix -ServerAddresses ("${var.domain_controller_ip}","127.0.0.1")
$here_string_password = @'
${var.domain_admin_password}
'@
$password = ConvertTo-SecureString $here_string_password -AsPlainText -Force
$username = "${local.domain_sld}\Administrator"
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
$server = Resolve-DnsName -Name _ldap._tcp.dc._msdcs.${var.active_directory_domain} -Type SRV | Where-Object {$_.Type -eq "A"} | Select -ExpandProperty Name
set-item wsman:localhost\client\trustedhosts *.${var.active_directory_domain} -Force
$s = New-PSSession -ComputerName $server -Credential $credential
Invoke-Command -Session $s -ScriptBlock { $server = Resolve-DnsName -Name _ldap._tcp.dc._msdcs.${var.active_directory_domain} -Type SRV | Where-Object {$_.Type -eq "A"} | Select -ExpandProperty Name }
Invoke-Command -Session $s -ScriptBlock { New-ADOrganizationalUnit -Name "RDP Member Servers" -Path "DC=${local.domain_sld},DC=${local.domain_tld}" -Server $server }
Invoke-Command -Session $s -ScriptBlock { New-GPO -Name "RDP Settings 01" }
Invoke-Command -Session $s -ScriptBlock { $GPOGuid = Get-gpo -name "RDP Settings 01" | Select -ExpandProperty Id }
Invoke-Command -Session $s -ScriptBlock { Set-GPRegistryValue -Guid $GPOGuid  -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDenyTSConnections" -Value 0 -Type DWord }
Invoke-Command -Session $s -ScriptBlock { New-GPLink -Guid $GPOGuid -Target "ou=RDP Member Servers,DC=${local.domain_sld},DC=${local.domain_tld}" -LinkEnabled Yes -Enforced Yes }
Remove-PSSession $s
Add-Computer -DomainName "${var.active_directory_domain}" -OUPath "ou=RDP Member Servers,DC=${local.domain_sld},DC=${local.domain_tld}" -Credential $credential

Restart-Computer -Force
                </powershell>
              EOF

  metadata_options {
    http_endpoint          = "enabled"
    instance_metadata_tags = "enabled"
  }
  get_password_data = true

  tags = {
    Name = "${var.prefix}-rdp-member-server-${local.username}"
  }
}

locals {
  password    = rsadecrypt(aws_instance.member_server.password_data, file(var.domain_controller_private_key))
  private_key = abspath(var.domain_controller_private_key)
}

resource "time_sleep" "wait_2_minutes" {
  depends_on      = [aws_instance.member_server]
  create_duration = "2m"
}

# wait for the SSH service to be available on the instance. We specifically use
# BatchMode=Yes to prevent SSH from prompting for a password to ensure that we
# can just SSH using the private key
resource "enos_local_exec" "wait_for_ssh" {
  depends_on = [time_sleep.wait_2_minutes]
  inline     = ["timeout 600s bash -c 'until ssh -i ${local.private_key} -o BatchMode=Yes -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.member_server.public_ip} \"echo ready\"; do sleep 10; done'"]
}

resource "enos_local_exec" "get_hostname" {
  depends_on = [
    enos_local_exec.wait_for_ssh,
  ]

  inline = ["ssh -i ${local.private_key} -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no Administrator@${aws_instance.member_server.public_ip} '$env:COMPUTERNAME'"]
}
