# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# Wait for AD Web Services to be available
$timeout = 600
$elapsed = 0
$interval = 15
while ($elapsed -lt $timeout) {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        Write-Host "Domain is ready: $($domain.Name)"
        break
    } catch {
        Write-Host "Domain not ready, waiting..."
        Start-Sleep -Seconds $interval
        $elapsed += $interval
    }
}
if ($elapsed -ge $timeout) {
    Write-Host "Timeout waiting for domain readiness"
    exit 1
}

$dnsName = $env:computername + '.' + "${active_directory_domain}"
$now = Get-Date

# Create self-signed certificate for LDAPS. Since it's not signed by a trusted
# CA, all LDAPS clients will have to allow insecure TLS.
#
# The -TextExtension is required. 2.5.29.37 is the OID for "Enhanced Key Usage"
# and we need to set it to 1.3.6.1.5.5.7.3.1 which is the OID for server
# authentication.
$cert = New-SelfSignedCertificate `
  -DnsName $dnsName `
  -NotAfter $now.AddYears(1) `
  -KeyUsage DigitalSignature, KeyEncipherment `
  -Type SSLServerAuthentication `
  -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
  -Provider "Microsoft Strong Cryptographic Provider" `
  -HashAlgorithm "SHA256"

# Copy certificate thumbprint to NTDS service store so that AD can use it.
$thumbprint = ($cert.Thumbprint | Out-String).Trim()
$certDestPath = 'HKLM:/Software/Microsoft/Cryptography/Services/NTDS/SystemCertificates/My/Certificates'
if (!(Test-Path $certDestPath)) { New-Item $certDestPath -Force }
Copy-Item `
  -Path HKLM:/Software/Microsoft/SystemCertificates/My/Certificates/$thumbprint `
  -Destination $certDestPath

# Signal NTDS that we have a new server certificate for use using an LDIF file.
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('dn:')
[void]$sb.AppendLine('changetype: modify')
[void]$sb.AppendLine('add: renewServerCertificate')
[void]$sb.AppendLine('renewServerCertificate: 1')
[void]$sb.AppendLine('-')

$sb.ToString() | Out-File -FilePath "rsc.ldif" -Encoding ASCII
ldifde -i -f rsc.ldif

# Create Vault user and add it to the domain administrators group for RDP
# access.
New-ADUser `
  -Enabled 1 `
  -Name ${vault_ldap_user} `
  -DisplayName ${vault_ldap_user} `
  -SamAccountName ${vault_ldap_user} `
  -PasswordNotRequired 1

Add-ADGroupMember -Identity 'Domain Admins' -Members ${vault_ldap_user}

# From here, a Vault LDAP engine can be configured to bind to the AD LDAPS
# server using the domain controller's credentials and then a static role
# for the Vault user above can be created. Additionally, a dynamic role
# can also be created using LDIF templates.
# The static/dynamic roles can then be used to RDP into the member server
# via Boundary Vault LDAP credential library.
