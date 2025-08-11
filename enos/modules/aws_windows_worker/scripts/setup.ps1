# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Unzip Boundary CLI to the same directory
$destination = Split-Path -Path ${boundary_cli_zip_path}
Expand-Archive -Path ${boundary_cli_zip_path} -DestinationPath $destination -Force

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


New-Item -Path ${test_dir}boundary_script.ps1 -ItemType File -Value 'boundary server -config ${test_dir}worker.hcl';
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NonInteractive -WindowStyle Hidden -File ${test_dir}boundary_script.ps1';
$trigger = New-ScheduledTaskTrigger -AtStartup;
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName boundary_task -User $env:COMPUTERNAME\$env:USERNAME -RunLevel Highest -Force;
schtasks /run /tn 'boundary_task';