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

#$trigger = New-JobTrigger -Once -At (Get-Date).AddSeconds(15)
#Register-ScheduledJob boundary { boundary server -config ${test_dir}worker.hcl } -trigger $trigger

$action = New-ScheduledTaskAction -Execute 'boundary' -Argument 'server -config ${test_dir}worker.hcl';
$trigger = New-ScheduledTaskTrigger -AtStartup;
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName boundary -User $env:COMPUTERNAME\$env:USERNAME -RunLevel Highest -Force;
schtasks /run /tn 'boundary';