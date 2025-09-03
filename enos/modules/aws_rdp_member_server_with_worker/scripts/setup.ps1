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

# create a trigger that will run boundary at startup
$trigger = New-JobTrigger -AtStartup
$configPath = Join-path ${test_dir} -ChildPath "worker.hcl"
$jobLog = Join-path ${test_dir} -ChildPath "worker.out"
$command = "boundary server -config `"$configPath`" *> $jobLog"
Register-ScheduledJob boundary -ScriptBlock ([ScriptBlock]::Create($command)) -Trigger $trigger

# Restart the computer to apply changes
shutdown -r -t 10
