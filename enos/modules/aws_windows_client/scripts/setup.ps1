# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# Unzip Boundary CLI to the same directory
Write-Host "Unzipping Boundary CLI..."
$destination = Split-Path -Path ${boundary_cli_zip_path}
Expand-Archive -Path ${boundary_cli_zip_path} -DestinationPath $destination -Force

# Unzip boundary src to new directory
Write-Host "Unzipping Boundary source code..."
$base = [System.IO.Path]::GetFileNameWithoutExtension("${boundary_src_zip_path}")
$src_destination = Join-Path (Split-Path ${boundary_src_zip_path}) $base
Expand-Archive -Path ${boundary_src_zip_path} -DestinationPath $src_destination -Force

# Add Boundary CLI to PATH
$existingPath = [Environment]::GetEnvironmentVariable(
    "Path",
    [EnvironmentVariableTarget]::Machine
)

$newPath = $existingPath + ";" + $destination
[Environment]::SetEnvironmentVariable(
    "Path",
    $newPath,
    [EnvironmentVariableTarget]::Machine
)

Write-Host "Checking if Vault needs to be installed..."
if ("${vault_version}" -ne "") {
    Write-Host "Installing Vault version ${vault_version}..."
    # Download and install Vault
    $vaultZipUrl = "https://releases.hashicorp.com/vault/${vault_version}/vault_${vault_version}_windows_amd64.zip"
    $vaultZipPath = Join-Path $destination "vault.zip"
    curl.exe -L -o $vaultZipPath $vaultZipUrl

    Expand-Archive -Path $vaultZipPath -DestinationPath $destination -Force
}

# Install chocolatey (package manager)
powershell -c "irm https://community.chocolatey.org/install.ps1|iex"

# Refreshes env to get choco on path
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
$env:ChocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."
Import-Module "$env:ChocolateyInstall/helpers/chocolateyInstaller.psm1"
refreshenv

# install mremoteng
choco install mremoteng -y

# install dependencies for rdp automated tests
choco install golang -y --version ${go_version}
refreshenv
choco install git -y
refreshenv
choco install mingw -y
refreshenv
# needs cmake >3.7 and <4.0
choco install cmake --version 3.31.8 -y
refreshenv

# Set the github token if provided
Write-Host "Checking if GitHub token is provided..."
if ("${github_token}" -ne "") {
    # configure git to be able to download from private repos
    git config --system url."https://oauth2:${github_token}@github.com".insteadOf "https://github.com"

    # download opencv artifact if available
    Write-Host "Downloading OpenCV artifact.."
    [Environment]::SetEnvironmentVariable("GITHUB_TOKEN", "${github_token}", [EnvironmentVariableTarget]::Machine)
    choco install gh -y
    refreshenv

    $repo = "hashicorp/boundary-enterprise"
    $workflow = "build-opencv-ent.yml"
    $branch = "main"
    $artifactName = "opencv-windows"

    $run = gh run list --repo $repo --workflow=$workflow --branch=$branch --status success --limit 1 --json databaseId | ConvertFrom-Json
    if (-not $run -or -not $run[0].databaseId) {
        Write-Error "Could not find a workflow run for $workflow in $repo."
        exit 1
    }
    Write-Host "Found workflow run: $($run[0])"
    $run_id = $run[0].databaseId

    New-Item -ItemType Directory -Path "C:/opencv/build" -Force
    $downloadResult = gh run download $run_id --repo $repo -n $artifactName --dir C:/opencv/build
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to download artifact $artifactName from workflow run $run_id."
        exit 1
    }

    # add opencv to path
    $existingPath = [Environment]::GetEnvironmentVariable(
        "Path",
        [EnvironmentVariableTarget]::Machine
    )
    $newPath = $existingPath + ";C:\opencv\build\install\x64\mingw\bin;"
    [Environment]::SetEnvironmentVariable(
        "Path",
        $newPath,
        [EnvironmentVariableTarget]::Machine
    )

    # go mod download
    Write-Host "Downloading Go modules at $src_destination..."
    cd $src_destination
    go mod download
}

# Setting default terminal app to Windows Terminal (modern terminal)
# aka Settings > System > For Developers > Terminal to Windows Terminal
# By default, Windows11 has preferred terminal app set as "Let Windows decide"
# which causes inconsistent terminal experience affecting images used for RDP tests
# Two properties need to be set in registry to change default terminal app
# DelegationTerminal determines which terminal UI to use
# DelegationConsole determines how the data is communicated between the terminal and the operating system
# (modern and legacy consoles have different communication protocols)
# For Windows Terminal (aka Modern Terminal)
# DelegationConsole ID: {2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}
# DelegationTerminal ID: {E12CFF52-A866-4C77-9A90-F570A7AA2C6B}
# For Console Host (aka Legacy Terminal)
# DelegationConsole ID: {B23D10C0-E52E-411E-9D5B-C09FDF709C7D}
# DelegationTerminal ID: {B23D10C0-E52E-411E-9D5B-C09FDF709C7D}
# For "Let Windows Decide" (default)
# remove both properties (DelegationConsole, DelegationTerminal)
$registryPath = "HKCU:\Console\%%Startup"
if (!(Test-Path $registryPath)) { New-Item -Path $registryPath -Force }
Set-ItemProperty -Path $registryPath -Name "DelegationConsole" -Value "{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}"
Set-ItemProperty -Path $registryPath -Name "DelegationTerminal" -Value "{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}"