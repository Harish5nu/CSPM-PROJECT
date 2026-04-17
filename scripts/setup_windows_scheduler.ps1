# scripts/setup_windows_scheduler.ps1
# Run as Administrator to set up scheduled task

$TaskName = "AI-AWS-CSPM-Security-Scan"
$ScriptPath = "$PSScriptRoot\run_automated.py"
$PythonPath = "$PSScriptRoot\..\venv\Scripts\python.exe"

# Create action
$Action = New-ScheduledTaskAction -Execute $PythonPath -Argument $ScriptPath

# Create trigger (daily at 9 AM)
$Trigger = New-ScheduledTaskTrigger -Daily -At 9am

# Create settings
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

# Register task
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Daily AWS Security Scan with AI Remediation"

Write-Host "✅ Scheduled task '$TaskName' created successfully!"
Write-Host "To test: Run 'python scripts/run_automated.py' manually first"