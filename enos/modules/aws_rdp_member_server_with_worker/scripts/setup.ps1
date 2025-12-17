# Copyright IBM Corp. 2020, 2025
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
$trigger = New-ScheduledTaskTrigger -AtStartup
$configPath = Join-path ${test_dir} -ChildPath "worker.hcl"
$jobLog = Join-path ${test_dir} -ChildPath "worker.out"

New-Item -Path C:/Test/worker_task.ps1 -ItemType File -Value "boundary server -config $configPath *> $jobLog"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File C:/Test/worker_task.ps1'
Register-ScheduledTask -TaskName "boundary" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force

# set the task to have no execution time limit
$Task = Get-ScheduledTask -TaskName "boundary"
$Task.Settings.ExecutionTimeLimit = "PT0H" # zero hours
Set-ScheduledTask $Task

# Restart the computer to apply changes
# Needed for adding the computer to the domain from the user_data script
shutdown -r -t 10
