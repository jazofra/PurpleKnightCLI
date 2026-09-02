<#
.SYNOPSIS
    Example wrapper for running Purple Knight from a scheduled task.

.DESCRIPTION
    Reads the Entra ID client secret from the Windows Credential Manager style
    encrypted file created by Save-PKSecret (below), runs the assessment, keeps the
    last 30 report folders and writes an event log entry summarising the result.

    Register with, for example:

        $action  = New-ScheduledTaskAction -Execute 'pwsh.exe' `
                     -Argument '-NoProfile -File "C:\ProgramData\Autodesk\PK Community 5.1\CLI\examples\Run-Scheduled.ps1"'
        $trigger = New-ScheduledTaskTrigger -Daily -At 3am
        Register-ScheduledTask -TaskName 'Purple Knight assessment' -Action $action -Trigger $trigger `
                     -User 'CORP\svc-purpleknight' -RunLevel Highest
#>
[CmdletBinding()]
param(
    [string] $ReportRoot = 'D:\Reports\PurpleKnight',
    [string] $SecretFile = "$env:ProgramData\PurpleKnight\entra-secret.xml",
    [int]    $KeepLastRuns = 30
)

$ErrorActionPreference = 'Stop'

$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-PurpleKnight.ps1'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputPath = Join-Path $ReportRoot $stamp

# The secret file is encrypted with DPAPI and can only be read back by the same
# account on the same machine. Create it once with:
#   Read-Host 'Client secret' -AsSecureString | Export-Clixml $SecretFile
if (Test-Path -LiteralPath $SecretFile) {
    $secure = Import-Clixml -LiteralPath $SecretFile
    $env:PK_TENANT_APP_SECRET = [System.Net.NetworkCredential]::new('', $secure).Password
}

try {
    & $cli -ConfigFile (Join-Path $PSScriptRoot 'pk-config.example.json') `
           -OutputPath $outputPath `
           -OutputFormat Json, Csv, Html
    $exitCode = $LASTEXITCODE
}
finally {
    Remove-Item Env:\PK_TENANT_APP_SECRET -ErrorAction SilentlyContinue
}

# Retention: keep only the newest $KeepLastRuns report folders.
Get-ChildItem -LiteralPath $ReportRoot -Directory |
    Sort-Object Name -Descending |
    Select-Object -Skip $KeepLastRuns |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

$summaryFile = Join-Path $outputPath 'purple-knight-results.json'
if (Test-Path -LiteralPath $summaryFile) {
    $summary = (Get-Content -LiteralPath $summaryFile -Raw | ConvertFrom-Json).Summary
    $scores = ($summary.Environments | ForEach-Object { "$($_.Environment) $($_.Score)% ($($_.Grade))" }) -join '; '
    Write-Host "Purple Knight: $($summary.Failed) of $($summary.Total) indicators of exposure found. $scores"
}

exit $exitCode
