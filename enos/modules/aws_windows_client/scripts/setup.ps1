# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Unzip Boundary CLI to the same directory
$destination = Split-Path -Path ${boundary_cli_zip_path}
Expand-Archive -Path ${boundary_cli_zip_path} -DestinationPath $destination -Force

# Unzip boundary src to new directory
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
if ("${github_token}" -ne "") {
    # configure git to be able to download from private repos
    git config --system url."https://oauth2:${github_token}@github.com".insteadOf "https://github.com"

    # download opencv artifact if available
    [Environment]::SetEnvironmentVariable("GITHUB_TOKEN", "${github_token}", [EnvironmentVariableTarget]::Machine)
    choco install gh -y
    refreshenv

    $repo = "hashicorp/boundary-enterprise"
    $workflow = "build-opencv-ent.yml"
    $branch = "main"
    $artifactName = "opencv"

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
}
