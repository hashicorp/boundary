[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[ValidateRange(1, 10000)]
	[int]$Count,

	[Parameter(Mandatory = $false)]
	[ValidateRange(1, 1000000)]
	[int]$StartAt = 1,

	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[string]$UsernamePrefix = "user",

	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[string]$PasswordPrefix = "p@ssw0rd00!",

	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[string]$AdminGroupName = "Domain Admins"
)

$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$domain = Get-ADDomain
$dnsRoot = $domain.DNSRoot
$createdUsers = 0

function Grant-AdminGroupMembership {
	param(
		[Parameter(Mandatory = $true)]
		[string]$SamAccountName
	)

	try {
		Add-ADGroupMember -Identity $AdminGroupName -Members $SamAccountName -ErrorAction Stop
		Write-Host "Granted domain admin access to user: $SamAccountName"
	}
	catch {
		if ($_.Exception.Message -match "already a member") {
			Write-Host "User '$SamAccountName' is already in '$AdminGroupName'."
		}
		else {
			throw
		}
	}
}




for ($i = $StartAt; $i -lt ($StartAt + $Count); $i++) {
	$username = "$UsernamePrefix$i"
	$plainPassword = "$PasswordPrefix$i"
	$securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force

	$existingUser = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
	if ($existingUser) {
		Write-Warning "User '$username' already exists. Skipping."
		Grant-AdminGroupMembership -SamAccountName $username
		continue
	}

	New-ADUser `
		-Name $username `
		-SamAccountName $username `
		-UserPrincipalName "$username@$dnsRoot" `
		-AccountPassword $securePassword `
		-Enabled $true `
		-PasswordNeverExpires $true

	$createdUsers++
	Write-Host "Created user: $username"

	Grant-AdminGroupMembership -SamAccountName $username

}

Write-Host "Done. Created $createdUsers user(s)."
