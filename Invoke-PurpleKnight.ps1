<#
.SYNOPSIS
    Runs Purple Knight security indicators from the command line.

.DESCRIPTION
    Purple Knight Community ships only as a desktop UI. Every one of its indicators is
    a self contained PowerShell script under <InstallPath>\Scripts, executed by the UI
    inside a runspace pool with a small set of connection parameters. This script does
    the same thing head-less, so a scheduled task or pipeline can produce the same
    findings, the same per indicator scores and the same security posture score.

    Nothing shipped by Semperis is modified: the original indicator scripts and the
    Semperis-Lib helper module are loaded and executed as-is.

.PARAMETER InstallPath
    Purple Knight installation directory. Defaults to the parent of this script, then
    $env:PURPLEKNIGHT_HOME, then the current directory.

.PARAMETER ConfigFile
    JSON file holding any of the parameters below. Useful for unattended runs so that
    secrets never appear on the command line or in the console history. Values passed
    explicitly on the command line win over the file.

.PARAMETER ListIndicators
    Print the indicator catalog and exit without running anything.

.PARAMETER Target
    Environments to assess: AD, EntraID (alias AAD/Entra) and/or Okta. When omitted the
    targets are inferred from the connection details supplied.

.PARAMETER Category
    Indicator categories to include; wildcards accepted (e.g. 'Kerberos*').

.PARAMETER Severity
    Severities to include: Critical, High, Medium, Low, Warning, Informational.

.PARAMETER Indicator
    Indicators to include, matched against script name, short name, display name, numeric
    ID or UUID. Wildcards accepted.

.PARAMETER ExcludeIndicator
    Indicators to exclude, matched the same way as -Indicator.

.PARAMETER IncludeUnselected
    Also run indicators that Purple Knight does not select by default.

.PARAMETER ForestName
    AD forest to assess. Auto-detected from the current machine when omitted.

.PARAMETER DomainNames
    Domains to assess. Auto-detected from the forest when omitted.

.PARAMETER DomainCredential
    Credential used for LDAP binds. Passed to the indicator scripts through the
    IOE_FOREST_CREDENTIALS environment variable that Semperis-Lib reads.

.PARAMETER TenantId
    Entra ID tenant id (GUID).

.PARAMETER TenantAppId
    Application (client) id of the Entra ID app registration used for the assessment.

.PARAMETER TenantAppSecret
    Client secret for that app registration.

.PARAMETER OktaDomain
    Okta domain, e.g. contoso.okta.com.

.PARAMETER OktaApiToken
    Okta API token.

.PARAMETER AttackWindowDays
    Size of the attack window used by the "recent change" indicators. Defaults to 30,
    matching AttackWindowDefaultNumOfDays in Settings.xml.

.PARAMETER ThrottleLimit
    Maximum number of indicators to run concurrently. 0 (default) uses the processor
    count, which is what the UI does when MaxRunspacePoolSize is 0.

.PARAMETER IndicatorTimeoutSeconds
    Per indicator timeout. Indicators still running after this are cancelled and
    reported with a Timeout status.

.PARAMETER OutputPath
    Directory for the reports. Defaults to <InstallPath>\Output\CLI-<timestamp>.

.PARAMETER OutputFormat
    Any of Console, Json, Csv, Html, None. Defaults to all four report types.

.PARAMETER FailOn
    Lowest severity of finding that should make the script exit with code 2.
    Use None (default) to always exit 0 unless the run itself failed.

.PARAMETER PassThru
    Emit the result objects on the pipeline.

.PARAMETER RefreshCatalog
    Rebuild the cached indicator catalog even if it is current.

.PARAMETER SkipPermissionCheck
    Skip the pre-flight Graph API permission check.

.PARAMETER CheckPermissionsOnly
    Report which Graph API permissions the selected indicators need, which are missing and
    which indicators each missing permission blocks, then exit without assessing anything.
    Exits 3 when permissions are missing and 1 when sign-in failed.

.EXAMPLE
    .\Invoke-PurpleKnight.ps1 -Target EntraID -TenantId <guid> -TenantAppId <guid> -TenantAppSecret <secret> -CheckPermissionsOnly

    Lists the Graph API permissions that are missing and the indicators they block,
    without running an assessment.

.EXAMPLE
    .\Invoke-PurpleKnight.ps1 -ListIndicators

    Show every indicator, its category, severity and target environment.

.EXAMPLE
    .\Invoke-PurpleKnight.ps1 -Target AD

    Run all Active Directory indicators against the current forest and write
    console, JSON, CSV and HTML reports.

.EXAMPLE
    .\Invoke-PurpleKnight.ps1 -Target EntraID -TenantId <guid> -TenantAppId <guid> -TenantAppSecret <secret>

    Run the Entra ID indicators only.

.EXAMPLE
    .\Invoke-PurpleKnight.ps1 -ConfigFile .\pk.json -OutputPath D:\Reports\PK -FailOn High

    Unattended run driven by a config file; exits 2 when any High or Critical
    indicator of exposure is found, which is convenient for CI or monitoring.

.EXAMPLE
    .\Invoke-PurpleKnight.ps1 -Indicator 'Kerberos*','*Delegation*' -OutputFormat Console

    Run a subset of indicators and only print to the console.
#>
#Requires -Version 7.0

[CmdletBinding()]
param(
    [string] $InstallPath,
    [string] $ConfigFile,

    [switch] $ListIndicators,

    [string[]] $Target,
    [string[]] $Category,
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Warning', 'Informational')]
    [string[]] $Severity,
    [string[]] $Indicator,
    [string[]] $ExcludeIndicator,
    [switch] $IncludeUnselected,

    [string] $ForestName,
    [string[]] $DomainNames,
    [pscredential] $DomainCredential,

    [string] $TenantId,
    [string] $TenantAppId,
    [string] $TenantAppSecret,

    [string] $OktaDomain,
    [string] $OktaApiToken,

    [ValidateRange(1, 365)]
    [int] $AttackWindowDays = 30,

    [ValidateRange(0, 256)]
    [int] $ThrottleLimit = 0,
    [ValidateRange(10, 86400)]
    [int] $IndicatorTimeoutSeconds = 900,

    [string] $OutputPath,
    [ValidateSet('Console', 'Json', 'Csv', 'Html', 'None')]
    [string[]] $OutputFormat = @('Console', 'Json', 'Csv', 'Html'),

    [ValidateSet('None', 'Any', 'Informational', 'Warning', 'Low', 'Medium', 'High', 'Critical')]
    [string] $FailOn = 'None',

    [switch] $PassThru,
    [switch] $RefreshCatalog,
    [switch] $SkipPermissionCheck,
    [switch] $CheckPermissionsOnly
)

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'PurpleKnightCli.psm1') -Force

#region parameter resolution --------------------------------------------------

# A config file lets scheduled runs keep secrets out of the command line. Anything
# passed explicitly on the command line takes precedence over the file.
if ($ConfigFile) {
    if (-not (Test-Path -LiteralPath $ConfigFile)) { throw "Config file not found: $ConfigFile" }
    $fileSettings = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json

    foreach ($property in $fileSettings.PSObject.Properties) {
        if ($PSBoundParameters.ContainsKey($property.Name)) { continue }
        if (-not (Get-Variable -Name $property.Name -Scope Script -ErrorAction SilentlyContinue)) { continue }
        Set-Variable -Name $property.Name -Scope Script -Value $property.Value
    }
}

# Environment variables are the most convenient way to inject secrets from a
# secret store or CI runner.
if (-not $TenantId -and $env:PK_TENANT_ID) { $TenantId = $env:PK_TENANT_ID }
if (-not $TenantAppId -and $env:PK_TENANT_APP_ID) { $TenantAppId = $env:PK_TENANT_APP_ID }
if (-not $TenantAppSecret -and $env:PK_TENANT_APP_SECRET) { $TenantAppSecret = $env:PK_TENANT_APP_SECRET }
if (-not $OktaDomain -and $env:PK_OKTA_DOMAIN) { $OktaDomain = $env:PK_OKTA_DOMAIN }
if (-not $OktaApiToken -and $env:PK_OKTA_API_TOKEN) { $OktaApiToken = $env:PK_OKTA_API_TOKEN }

$resolvedInstall = Resolve-PKInstallPath -InstallPath $InstallPath
Write-Verbose "Purple Knight installation: $resolvedInstall"

#endregion

#region runtime preparation ---------------------------------------------------

# Semperis-Lib and every indicator module live under Scripts. Appending (rather than
# prepending) keeps the built-in PowerShell modules ahead of the stub manifests that
# Purple Knight ships for its self-contained host.
$scriptsRoot = Join-Path $resolvedInstall 'Scripts'
if (($env:PSModulePath -split [IO.Path]::PathSeparator) -notcontains $scriptsRoot) {
    $env:PSModulePath = $env:PSModulePath.TrimEnd([IO.Path]::PathSeparator) + [IO.Path]::PathSeparator + $scriptsRoot
}

$resultAssembly = Get-PKResultTypeAssembly -InstallPath $resolvedInstall
Initialize-PKResultType -AssemblyPath $resultAssembly

$catalog = @(Get-PKIndicatorCatalog -InstallPath $resolvedInstall -Refresh:$RefreshCatalog)
if ($catalog.Count -eq 0) { throw "No indicators were found under $scriptsRoot." }

if ($ListIndicators) {
    Select-PKIndicator -Catalog $catalog -Target $Target -Category $Category -Severity $Severity `
        -Indicator $Indicator -ExcludeIndicator $ExcludeIndicator -IncludeUnselected:$IncludeUnselected |
        Sort-Object Category, Name |
        Select-Object ID, ShortName, ScriptName, Name, Category, Severity,
            @{ N = 'Targets'; E = { $_.Targets -join ',' } }, Selected, Version
    return
}

#endregion

#region connection context ----------------------------------------------------

$targetCodes = if ($Target) { @($Target | ForEach-Object { ConvertTo-PKTargetCode $_ }) } else { @() }

# Discover the local forest only when AD indicators are actually going to run.
$wantsAD = (-not $targetCodes) -or ($targetCodes -contains 'AD')
if ($wantsAD -and -not $ForestName) {
    try {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $ForestName = $forest.Name
        if (-not $DomainNames) { $DomainNames = @($forest.Domains | ForEach-Object { $_.Name }) }
        Write-Verbose "Auto-detected forest '$ForestName' with domains: $($DomainNames -join ', ')"
    }
    catch {
        Write-Warning "Active Directory indicators will be skipped: $($_.Exception.Message)"
    }
}

if ($ForestName -and -not $DomainNames) { $DomainNames = @($ForestName) }

$attackWindowEnd = (Get-Date).ToUniversalTime()
$attackWindowStart = $attackWindowEnd.AddDays(-$AttackWindowDays)

$context = @{
    ForestName        = $ForestName
    DomainNames       = $DomainNames
    TenantId          = $TenantId
    TenantAppId       = $TenantAppId
    TenantAppSecret   = $TenantAppSecret
    OktaDomain        = $OktaDomain
    OktaApiToken      = $OktaApiToken
    StartAttackWindow = $attackWindowStart
    EndAttackWindow   = $attackWindowEnd
}

# Semperis-Lib picks up alternate LDAP credentials from this variable, keyed by domain.
if ($DomainCredential -and $DomainNames) {
    $credentialMap = @{}
    foreach ($domain in $DomainNames) {
        $credentialMap[$domain] = @{
            UserName = $DomainCredential.UserName
            Password = $DomainCredential.GetNetworkCredential().Password
        }
    }
    $env:IOE_FOREST_CREDENTIALS = $credentialMap | ConvertTo-Json -Compress
}

# When no explicit target was given, assess whichever environments we can reach.
if (-not $targetCodes) {
    if ($ForestName) { $targetCodes += 'AD' }
    if ($TenantId -and $TenantAppId -and $TenantAppSecret) { $targetCodes += 'AAD' }
    if ($OktaDomain -and $OktaApiToken) { $targetCodes += 'Okta' }
    if (-not $targetCodes) {
        throw 'No environment could be determined. Supply -Target and the matching connection parameters (-ForestName / -TenantId / -OktaDomain).'
    }
    Write-Verbose "Inferred targets: $($targetCodes -join ', ')"
}

#endregion

#region execution -------------------------------------------------------------

$selected = @(Select-PKIndicator -Catalog $catalog -Target $targetCodes -Category $Category -Severity $Severity `
    -Indicator $Indicator -ExcludeIndicator $ExcludeIndicator -IncludeUnselected:$IncludeUnselected)

if ($selected.Count -eq 0) { throw 'No indicators matched the supplied filters.' }

# Warn about missing Graph permissions before spending time on the run, so a partial
# assessment is obvious up front rather than being buried in per indicator errors.
$permissionReport = $null
$needsGraph = @($selected | Where-Object { $_.Targets -contains 'AAD' }).Count -gt 0

if ($needsGraph -and -not $SkipPermissionCheck) {
    if ($TenantId -and $TenantAppId -and $TenantAppSecret) {
        Write-Host 'Checking Graph API permissions...' -ForegroundColor DarkGray
        $permissionContext = Get-PKGraphPermissionContext -TenantId $TenantId -TenantAppId $TenantAppId -TenantAppSecret $TenantAppSecret
        $permissionReport = Get-PKPermissionReport -Indicators $selected -Context $permissionContext
        Write-PKPermissionReport -Report $permissionReport -Detailed:$CheckPermissionsOnly
    }
    elseif ($CheckPermissionsOnly) {
        throw 'The permission check needs -TenantId, -TenantAppId and -TenantAppSecret.'
    }
}

if ($CheckPermissionsOnly) {
    if ($PassThru) { $permissionReport }
    if (-not $permissionReport) { exit 1 }
    if (-not $permissionReport.Authenticated) { exit 1 }
    exit $(if ($permissionReport.Missing.Count -gt 0) { 3 } else { 0 })
}

# Sign-in failed, so every Entra ID indicator is guaranteed to fail. Drop them rather than
# spending time collecting the same 401 dozens of times.
if ($permissionReport -and -not $permissionReport.Authenticated) {
    $stillViable = @($selected | Where-Object { $_.Targets -notcontains 'AAD' })

    if ($stillViable.Count -eq 0) {
        Write-Host 'Aborting: sign-in failed, so none of the selected indicators can run.' -ForegroundColor Red
        Write-Host 'Fix the credentials above, or pass -SkipPermissionCheck to run anyway.' -ForegroundColor DarkGray
        exit 1
    }

    Write-Host ("Skipping {0} Entra ID indicator(s) because sign-in failed; continuing with {1}." -f `
        ($selected.Count - $stillViable.Count), $stillViable.Count) -ForegroundColor Yellow
    $selected = $stillViable
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $resolvedInstall ('Output\CLI-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$null = New-Item -ItemType Directory -Force -Path $OutputPath

Write-Host "Purple Knight CLI - running $($selected.Count) indicators against $($targetCodes -join ', ')" -ForegroundColor Cyan

$stopwatch = [Diagnostics.Stopwatch]::StartNew()
try {
    $results = @(Invoke-PKIndicatorSet -Indicators $selected -InstallPath $resolvedInstall -Context $context `
        -ResultAssemblyPath $resultAssembly -ConfigLocation $resolvedInstall `
        -ThrottleLimit $ThrottleLimit -IndicatorTimeoutSeconds $IndicatorTimeoutSeconds)
}
finally {
    $stopwatch.Stop()
    Remove-Item Env:\IOE_FOREST_CREDENTIALS -ErrorAction SilentlyContinue
}

$summary = Get-PKSummary -Results $results

$runInfo = [pscustomobject]@{
    GeneratedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName      = [Environment]::MachineName
    RunAs             = [Environment]::UserName
    InstallPath       = $resolvedInstall
    Targets           = @($targetCodes)
    ForestName        = $ForestName
    DomainNames       = @($DomainNames)
    TenantId          = $TenantId
    OktaDomain        = $OktaDomain
    AttackWindowDays  = $AttackWindowDays
    AttackWindowStart = $attackWindowStart.ToString('o')
    AttackWindowEnd   = $attackWindowEnd.ToString('o')
    IndicatorCount    = $selected.Count
    DurationSeconds   = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
}

#endregion

#region reporting -------------------------------------------------------------

if ($OutputFormat -notcontains 'None') {
    if ($OutputFormat -contains 'Console') {
        Write-PKConsoleReport -Results $results -Summary $summary
    }
    if ($OutputFormat -contains 'Json') {
        $file = Export-PKJsonReport -Results $results -Summary $summary -RunInfo $runInfo -PermissionReport $permissionReport -Path (Join-Path $OutputPath 'purple-knight-results.json')
        Write-Host "JSON report : $file"
    }
    if ($OutputFormat -contains 'Csv') {
        $file = Export-PKCsvReport -Results $results -Path (Join-Path $OutputPath 'purple-knight-summary.csv') -DetailDirectory (Join-Path $OutputPath 'details')
        Write-Host "CSV report  : $file"
    }
    if ($OutputFormat -contains 'Html') {
        $file = Export-PKHtmlReport -Results $results -Summary $summary -RunInfo $runInfo -Path (Join-Path $OutputPath 'purple-knight-report.html')
        Write-Host "HTML report : $file"
    }
}

Write-Host "Completed in $($runInfo.DurationSeconds)s." -ForegroundColor Cyan

if ($PassThru) {
    [pscustomobject]@{
        Run             = $runInfo
        Summary         = $summary
        Indicators      = @(Get-PKSortedResult -Results $results)
        PermissionCheck = $permissionReport
    }
}

#endregion

#region exit code -------------------------------------------------------------

$exitCode = 0

$evaluated = @($results | Where-Object Status -in @('Pass', 'Failed'))

if ($evaluated.Count -eq 0) {
    # Nothing could be assessed: a connectivity, credential or permissions problem rather
    # than a finding. Say which, otherwise the report looks like an empty success.
    $skipped = @($results | Where-Object Status -eq 'Skipped')
    $denied  = @($results | Where-Object { $_.ResultMessage -match 'Insufficient permissions' })
    $errored = @($results | Where-Object Status -in @('Error', 'Timeout'))

    Write-Host ''
    Write-Host "No indicator produced an assessment ($($results.Count) selected)." -ForegroundColor Red

    if ($skipped.Count -eq $results.Count) {
        Write-Host '  Every indicator was skipped because the connection details it needs were not supplied.' -ForegroundColor Red
        Write-Host '  Check the "skipped" section above for the exact parameters that are missing.' -ForegroundColor DarkGray
        Write-Host '  Values can come from the command line, -ConfigFile, or the PK_* environment variables.' -ForegroundColor DarkGray
    }
    elseif ($denied.Count -gt 0 -and $denied.Count -eq $errored.Count) {
        Write-Host '  Every indicator was blocked by missing Graph API permissions. Grant the permissions listed above.' -ForegroundColor Red
    }
    else {
        Write-Host '  Check connectivity, credentials and permissions. The JSON report holds the full error for each indicator.' -ForegroundColor DarkGray
    }
    $exitCode = 1
}
elseif ($FailOn -ne 'None') {
    $severityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Warning = 4; Informational = 5 }
    $threshold = if ($FailOn -eq 'Any') { 5 } else { $severityRank[$FailOn] }

    $triggering = @($results | Where-Object {
        $_.Status -eq 'Failed' -and $severityRank.ContainsKey($_.Severity) -and $severityRank[$_.Severity] -le $threshold
    })

    if ($triggering.Count -gt 0) {
        Write-Host "$($triggering.Count) indicator(s) at or above severity '$FailOn' were found." -ForegroundColor Red
        $exitCode = 2
    }
}

exit $exitCode

#endregion
