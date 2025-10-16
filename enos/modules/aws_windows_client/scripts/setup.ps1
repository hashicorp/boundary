# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Unzip Boundary CLI to the same directory
$destination = Split-Path -Path ${boundary_cli_zip_path}
Expand-Archive -Path ${boundary_cli_zip_path} -DestinationPath $destination -Force

# Unzip boundary src to new directory
$src_destination = "C:/Test/boundary-src"
New-Item -Path $src_destination -ItemType Directory
Expand-Archive -Path C:/Test//boundary-src.zip -DestinationPath $src_destination -Force

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

# Install chocolatey (package manager)
powershell -c "irm https://community.chocolatey.org/install.ps1|iex"

# Refreshes env to get choco on path
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
$env:ChocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."
Import-Module "$env:ChocolateyInstall/helpers/chocolateyInstaller.psm1"
refreshenv

# install mremoteng
choco install mremoteng -y

# powershell script
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
if ("${github_token}" -ne "") {
    git config --system url."https://oauth2:${github_token}@github.com".insteadOf "https://github.com"
}