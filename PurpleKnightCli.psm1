#Requires -Version 7.0
<#
.SYNOPSIS
    Core library for the Purple Knight CLI runner.
.DESCRIPTION
    Purple Knight Community ships as a WPF desktop application with no command line
    interface. All of its security indicators are, however, plain PowerShell scripts
    that live under <InstallPath>\Scripts and share a common helper module
    (Semperis-Lib). This module reproduces the parts of the desktop application that
    are needed to run those indicators head-less:

      * indicator discovery + metadata extraction (via each script's -Metadata switch)
      * a runspace pool executor equivalent to the application's MaxRunspacePoolSize
      * Purple Knight's exact security posture scoring and grading algorithm
      * report generation (JSON / CSV / HTML)

    The indicator scripts themselves are never modified, so results are identical to
    the ones produced by the UI.
#>

Set-StrictMode -Version Latest

#region constants -------------------------------------------------------------

# Severity constants lifted from ReportGeneration.ResultsStore.RiskAssessment.
# The per-indicator residual is 1 - basePenalty * exposure, so basePenalty doubles as the
# rate at which each additional finding of a severity erodes that severity's headroom.
$script:PKBasePenalty = @{
    Informational = 0.00
    Warning       = 0.00
    Low           = 0.05
    Medium        = 0.09
    High          = 0.14
    Critical      = 0.20
}

$script:PKSeverityWeight = @{
    Informational = 0.00
    Warning       = 0.00
    Low           = 0.02
    Medium        = 0.10
    High          = 0.33
    Critical      = 0.55
}

# Thresholds from ReportGeneration.ResultsStore.Helpers.ResultsStoreHelper.GetGrade.
$script:PKGradeTable = @(
    @{ Min = 100; Grade = 'A+' }
    @{ Min =  99; Grade = 'A'  }
    @{ Min =  98; Grade = 'A-' }
    @{ Min =  96; Grade = 'B+' }
    @{ Min =  93; Grade = 'B'  }
    @{ Min =  90; Grade = 'B-' }
    @{ Min =  86; Grade = 'C+' }
    @{ Min =  81; Grade = 'C'  }
    @{ Min =  75; Grade = 'C-' }
    @{ Min =  67; Grade = 'D+' }
    @{ Min =  58; Grade = 'D'  }
    @{ Min =  44; Grade = 'D-' }
    @{ Min =   0; Grade = 'F'  }
)

$script:PKSeverityOrder = @{
    Critical = 0; High = 1; Medium = 2; Low = 3; Warning = 4; Informational = 5
}

# Purple Knight internal target codes -> friendly environment names.
$script:PKTargetNames = @{
    AD   = 'Active Directory'
    AAD  = 'Entra ID'
    Okta = 'Okta'
}

# Every parameter an indicator script may declare.
$script:PKKnownParameters = @(
    'ForestName', 'DomainNames',
    'TenantId', 'TenantAppId', 'TenantAppSecret',
    'OktaDomain', 'OktaApiToken',
    'StartAttackWindow', 'EndAttackWindow'
)

$script:PKResultTypeName = 'Semperis.PSSecurityIndicatorResult.SecurityIndicatorResult'

#endregion

#region installation discovery ------------------------------------------------

function Resolve-PKInstallPath {
    <#
    .SYNOPSIS
        Locates a Purple Knight installation directory.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $InstallPath
    )

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($InstallPath) { $candidates.Add($InstallPath) }
    if ($PSScriptRoot) { $candidates.Add((Split-Path -Parent $PSScriptRoot)) }
    if ($env:PURPLEKNIGHT_HOME) { $candidates.Add($env:PURPLEKNIGHT_HOME) }
    $candidates.Add((Get-Location).Path)

    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        if (Test-Path -LiteralPath (Join-Path $candidate 'Scripts\Scripts.config.xml')) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "Could not locate a Purple Knight installation. Pass -InstallPath, or set PURPLEKNIGHT_HOME. Looked in: $($candidates -join '; ')"
}

function Get-PKResultTypeAssembly {
    <#
    .SYNOPSIS
        Finds Semperis.PSSecurityIndicatorResult.dll, which defines the result object
        that every indicator returns.
    .DESCRIPTION
        The DLL is embedded in the single-file PurpleKnight.exe and is extracted to
        %TEMP%\.net\PurpleKnight\<hash>\ the first time the UI runs. A copy is kept in
        <InstallPath>\CLI\lib so the CLI does not depend on that volatile location.
        When no copy can be found a functionally identical type is compiled on the fly.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $InstallPath,
        [string] $LibraryPath
    )

    $searchDirs = [System.Collections.Generic.List[string]]::new()
    if ($LibraryPath) { $searchDirs.Add($LibraryPath) }
    $searchDirs.Add((Join-Path $InstallPath 'CLI\lib'))

    foreach ($dir in $searchDirs) {
        $dll = Join-Path $dir 'Semperis.PSSecurityIndicatorResult.dll'
        if (Test-Path -LiteralPath $dll) { return (Resolve-Path -LiteralPath $dll).Path }
    }

    # Fall back to the extraction directory of the desktop application, and cache it.
    $extracted = Get-ChildItem -Path (Join-Path $env:TEMP '.net\PurpleKnight') -Recurse `
        -Filter 'Semperis.PSSecurityIndicatorResult.dll' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($extracted) {
        $cacheDir = Join-Path $InstallPath 'CLI\lib'
        try {
            $null = New-Item -ItemType Directory -Force -Path $cacheDir
            Copy-Item -LiteralPath $extracted.FullName -Destination $cacheDir -Force
            return (Join-Path $cacheDir 'Semperis.PSSecurityIndicatorResult.dll')
        }
        catch {
            return $extracted.FullName
        }
    }

    return $null
}

function Initialize-PKResultType {
    <#
    .SYNOPSIS
        Makes the SecurityIndicatorResult type available to the current process.
    #>
    [CmdletBinding()]
    param(
        [string] $AssemblyPath
    )

    if ($script:PKResultTypeName -as [type]) { return }

    if ($AssemblyPath -and (Test-Path -LiteralPath $AssemblyPath)) {
        Add-Type -Path $AssemblyPath
        return
    }

    Write-Verbose 'Semperis.PSSecurityIndicatorResult.dll not found - compiling an equivalent type.'
    Add-Type -TypeDefinition @'
namespace Semperis.PSSecurityIndicatorResult
{
    public enum ScriptStatus { Failed = 0, Pass = 1, Error = 2, NotRelevant = 3 }

    public class SecurityIndicatorResult
    {
        public ScriptStatus Status { get; set; }
        public int Score { get; set; }
        public string ResultMessage { get; set; }
        public string Remediation { get; set; }
        public System.Management.Automation.PSObject[] ResultObjects { get; set; }
        public string Filename { get; set; }
    }
}
'@ -ReferencedAssemblies 'System.Management.Automation'
}

#endregion

#region indicator catalog -----------------------------------------------------

function Get-PKCategoryMap {
    <#
    .SYNOPSIS
        Returns a CategoryID -> category metadata lookup.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $InstallPath
    )

    $map = @{}

    $bundle = Get-ChildItem -Path (Join-Path $InstallPath 'Scripts') -Directory -Filter 'Semperis.PK.SI.*' -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ChildItem -Path $_.FullName -Recurse -Filter 'metadata.json' -ErrorAction SilentlyContinue } |
        Select-Object -First 1

    if ($bundle) {
        $meta = Get-Content -LiteralPath $bundle.FullName -Raw | ConvertFrom-Json
        foreach ($category in $meta.Categories) {
            $map[[int]$category.Id] = [pscustomobject]@{
                ID     = [int]$category.Id
                Name   = [string]$category.Name
                Weight = [int]$category.Weight
            }
        }
    }

    if ($map.Count -eq 0) {
        $configPath = Join-Path $InstallPath 'Scripts\Scripts.config.xml'
        if (Test-Path -LiteralPath $configPath) {
            [xml]$config = Get-Content -LiteralPath $configPath
            foreach ($category in $config.Configuration.Categories.Category) {
                $map[[int]$category.ID] = [pscustomobject]@{
                    ID     = [int]$category.ID
                    Name   = [string]$category.Name
                    Weight = [int]$category.Weight
                }
            }
        }
    }

    return $map
}

function Get-PKIndicatorScriptFile {
    <#
    .SYNOPSIS
        Returns the newest indicator script for every Semperis.SI.* module folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $InstallPath
    )

    $scriptsRoot = Join-Path $InstallPath 'Scripts'
    foreach ($module in Get-ChildItem -LiteralPath $scriptsRoot -Directory -Filter 'Semperis.SI.*') {
        $shortName = $module.Name -replace '^Semperis\.SI\.', ''

        $versionDir = Get-ChildItem -LiteralPath $module.FullName -Directory -ErrorAction SilentlyContinue |
            Sort-Object { try { [version]($_.Name -replace '[^0-9\.].*$', '') } catch { [version]'0.0' } } -Descending |
            Select-Object -First 1
        if (-not $versionDir) { continue }

        $scriptFile = Join-Path $versionDir.FullName "$shortName.ps1"
        if (-not (Test-Path -LiteralPath $scriptFile)) {
            $scriptFile = (Get-ChildItem -LiteralPath $versionDir.FullName -Filter '*.ps1' | Select-Object -First 1).FullName
        }
        if (-not $scriptFile -or -not (Test-Path -LiteralPath $scriptFile)) { continue }

        [pscustomobject]@{
            ModuleName = $module.Name
            ScriptName = $shortName
            Version    = $versionDir.Name
            Path       = $scriptFile
        }
    }
}

function Get-PKScriptParameterName {
    <#
    .SYNOPSIS
        Reads the parameter names an indicator script declares, without executing it.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)

    $paramBlock = $ast.ParamBlock
    if (-not $paramBlock) { return @() }

    return @($paramBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
}

function Get-PKIndicatorCatalog {
    <#
    .SYNOPSIS
        Discovers every indicator shipped with the installation and returns its metadata.
    .DESCRIPTION
        Metadata is obtained by invoking each indicator script with its -Metadata switch,
        which is exactly how the desktop application enumerates indicators. Results are
        cached in <InstallPath>\CLI\cache so subsequent runs start instantly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $InstallPath,
        [switch] $Refresh
    )

    $cacheFile = Join-Path $InstallPath 'CLI\cache\indicator-catalog.json'
    $scriptFiles = @(Get-PKIndicatorScriptFile -InstallPath $InstallPath)
    $signature = ($scriptFiles | ForEach-Object { "$($_.ModuleName)|$($_.Version)" } | Sort-Object) -join ';'

    if (-not $Refresh -and (Test-Path -LiteralPath $cacheFile)) {
        try {
            $cached = Get-Content -LiteralPath $cacheFile -Raw | ConvertFrom-Json
            if ($cached.Signature -eq $signature) {
                Write-Verbose "Loaded indicator catalog from cache ($($cached.Indicators.Count) indicators)."
                return @($cached.Indicators)
            }
        }
        catch {
            Write-Verbose "Ignoring unreadable catalog cache: $($_.Exception.Message)"
        }
    }

    $categories = Get-PKCategoryMap -InstallPath $InstallPath
    $catalog = [System.Collections.Generic.List[object]]::new()
    $index = 0

    foreach ($file in $scriptFiles) {
        $index++
        Write-Progress -Activity 'Discovering Purple Knight indicators' -Status $file.ScriptName `
            -PercentComplete (100 * $index / [Math]::Max(1, $scriptFiles.Count))

        try {
            $json = & $file.Path -Metadata 2>$null
            if (-not $json) { throw 'The script returned no metadata.' }
            $meta = $json | ConvertFrom-Json
        }
        catch {
            Write-Warning "Skipping $($file.ScriptName): unable to read metadata - $($_.Exception.Message)"
            continue
        }

        $categoryId = if ($meta.PSObject.Properties.Name -contains 'CategoryID') { [int]$meta.CategoryID } else { 0 }
        $categoryName = if ($categories.ContainsKey($categoryId)) { $categories[$categoryId].Name } else { 'Uncategorized' }

        $catalog.Add([pscustomobject]@{
            ID              = if ($meta.PSObject.Properties.Name -contains 'ID') { [int]$meta.ID } else { 0 }
            UUID            = [string]$meta.UUID
            ShortName       = [string]$meta.ShortName
            ScriptName      = $file.ScriptName
            Name            = [string]$meta.Name
            CategoryID      = $categoryId
            Category        = $categoryName
            Severity        = [string]$meta.Severity
            Weight          = if ($meta.PSObject.Properties.Name -contains 'Weight') { [int]$meta.Weight } else { 0 }
            Impact          = if ($meta.PSObject.Properties.Name -contains 'Impact') { [int]$meta.Impact } else { 0 }
            Targets         = @($meta.Targets)
            DataSources     = @($meta.DataSources)
            Permissions     = @($meta.Permissions)
            Types           = @($meta.Types)
            Selected        = [bool]([int]$meta.Selected)
            Version         = $file.Version
            ModuleName      = $file.ModuleName
            Path            = $file.Path
            ScriptParameters= @(Get-PKScriptParameterName -Path $file.Path)
            Description     = [string]$meta.Description
            Remediation     = [string]$meta.Remediation
        })
    }

    Write-Progress -Activity 'Discovering Purple Knight indicators' -Completed

    try {
        $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $cacheFile)
        [pscustomobject]@{
            Signature   = $signature
            GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
            Indicators  = $catalog
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $cacheFile -Encoding UTF8
    }
    catch {
        Write-Verbose "Could not write catalog cache: $($_.Exception.Message)"
    }

    return @($catalog)
}

function Select-PKIndicator {
    <#
    .SYNOPSIS
        Applies the CLI's selection filters to the indicator catalog.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Catalog,
        [string[]] $Target,
        [string[]] $Category,
        [string[]] $Severity,
        [string[]] $Indicator,
        [string[]] $ExcludeIndicator,
        [switch] $IncludeUnselected
    )

    $result = $Catalog

    if (-not $IncludeUnselected) {
        $result = @($result | Where-Object { $_.Selected })
    }

    if ($Target) {
        $wanted = @($Target | ForEach-Object { ConvertTo-PKTargetCode $_ })
        $result = @($result | Where-Object {
            $indicatorTargets = $_.Targets
            @($indicatorTargets | Where-Object { $wanted -contains $_ }).Count -gt 0
        })
    }

    if ($Category) {
        $result = @($result | Where-Object {
            $name = $_.Category
            @($Category | Where-Object { $name -like $_ }).Count -gt 0
        })
    }

    if ($Severity) {
        $result = @($result | Where-Object { $Severity -contains $_.Severity })
    }

    if ($Indicator) {
        $result = @($result | Where-Object { Test-PKIndicatorMatch -Indicator $_ -Patterns $Indicator })
    }

    if ($ExcludeIndicator) {
        $result = @($result | Where-Object { -not (Test-PKIndicatorMatch -Indicator $_ -Patterns $ExcludeIndicator) })
    }

    return @($result)
}

function Test-PKIndicatorMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] $Indicator,
        [Parameter(Mandatory)] [string[]] $Patterns
    )

    foreach ($pattern in $Patterns) {
        if ($Indicator.ScriptName -like $pattern) { return $true }
        if ($Indicator.ShortName -like $pattern) { return $true }
        if ($Indicator.Name -like $pattern) { return $true }
        if ("$($Indicator.ID)" -eq $pattern) { return $true }
        if ($Indicator.UUID -like $pattern) { return $true }
    }
    return $false
}

function ConvertTo-PKTargetCode {
    <#
    .SYNOPSIS
        Normalises user supplied environment names to Purple Knight target codes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Name)

    switch -Regex ($Name) {
        '^(ad|activedirectory|active directory)$'          { return 'AD' }
        '^(aad|entra|entraid|entra id|azuread|azure ad)$'   { return 'AAD' }
        '^okta$'                                           { return 'Okta' }
        default                                            { return $Name }
    }
}

#endregion

#region execution -------------------------------------------------------------

function New-PKRunspacePool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $InstallPath,
        [int] $ThrottleLimit
    )

    if ($ThrottleLimit -le 0) { $ThrottleLimit = [Environment]::ProcessorCount }

    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $sessionState.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread

    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit, $sessionState, $Host)
    $pool.Open()
    return $pool
}

function Get-PKIndicatorArgument {
    <#
    .SYNOPSIS
        Builds the parameter splat for one indicator from the available connection details.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] $Indicator,
        [Parameter(Mandatory)] [hashtable] $Context
    )

    $arguments = @{}
    foreach ($name in $Indicator.ScriptParameters) {
        if ($script:PKKnownParameters -notcontains $name) { continue }
        if (-not $Context.ContainsKey($name)) { continue }
        if ($null -eq $Context[$name]) { continue }
        $arguments[$name] = $Context[$name]
    }
    return $arguments
}

function Test-PKIndicatorRunnable {
    <#
    .SYNOPSIS
        Determines whether the connection details required by an indicator are present.
    .DESCRIPTION
        Returns $null when the indicator can run, otherwise a message naming exactly which
        values are missing, so a skipped indicator can explain itself in the report.

        The decision is based on the indicator's Targets metadata, not on its declared
        parameters: Purple Knight gives every script the same param block, so the Entra ID
        indicators all declare ForestName and DomainNames even though they never use them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Indicator,
        [Parameter(Mandatory)] [hashtable] $Context
    )

    $targets = @($Indicator.Targets)
    $parameters = @($Indicator.ScriptParameters)
    $missing = [ordered]@{}

    if ($targets -contains 'AD') {
        if ($parameters -contains 'ForestName'  -and -not $Context['ForestName'])  { $missing['-ForestName'] = $true }
        if ($parameters -contains 'DomainNames' -and -not $Context['DomainNames']) { $missing['-DomainNames'] = $true }
    }

    # The Entra ID indicators need all three values; a partial set fails later with an
    # opaque token error, so treat it as missing input here instead.
    if ($targets -contains 'AAD' -and $parameters -contains 'TenantId') {
        if (-not $Context['TenantId'])        { $missing['-TenantId'] = $true }
        if (-not $Context['TenantAppId'])     { $missing['-TenantAppId'] = $true }
        if (-not $Context['TenantAppSecret']) { $missing['-TenantAppSecret'] = $true }
    }

    if ($targets -contains 'Okta') {
        if ($parameters -contains 'OktaDomain'   -and -not $Context['OktaDomain'])   { $missing['-OktaDomain'] = $true }
        if ($parameters -contains 'OktaApiToken' -and -not $Context['OktaApiToken']) { $missing['-OktaApiToken'] = $true }
    }

    if ($missing.Count -eq 0) { return $null }

    return 'Not run: no value was supplied for {0}.' -f (@($missing.Keys) -join ', ')
}

function Invoke-PKIndicatorSet {
    <#
    .SYNOPSIS
        Runs the selected indicators in parallel and returns one result object each.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Indicators,
        [Parameter(Mandatory)] [string] $InstallPath,
        [Parameter(Mandatory)] [hashtable] $Context,
        [string] $ResultAssemblyPath,
        [string] $ConfigLocation,
        [int] $ThrottleLimit = 0,
        [int] $IndicatorTimeoutSeconds = 900
    )

    $worker = {
        param($ScriptPath, $Arguments, $AssemblyPath, $Location, $StateBag, $Key)

        $StateBag[$Key] = [datetime]::UtcNow
        if ($AssemblyPath -and -not ('Semperis.PSSecurityIndicatorResult.SecurityIndicatorResult' -as [type])) {
            Add-Type -Path $AssemblyPath -ErrorAction SilentlyContinue
        }
        if ($Location) { Set-Location -LiteralPath $Location }
        & $ScriptPath @Arguments
    }

    $pool = New-PKRunspacePool -InstallPath $InstallPath -ThrottleLimit $ThrottleLimit
    $startTimes = [hashtable]::Synchronized(@{})
    $jobs = [System.Collections.Generic.List[object]]::new()
    $results = [System.Collections.Generic.List[object]]::new()

    try {
        foreach ($indicator in $Indicators) {
            $skipReason = Test-PKIndicatorRunnable -Indicator $indicator -Context $Context
            if ($skipReason) {
                $results.Add((New-PKResult -Indicator $indicator -Status 'Skipped' -ResultMessage $skipReason))
                continue
            }

            $arguments = Get-PKIndicatorArgument -Indicator $indicator -Context $Context

            $shell = [powershell]::Create()
            $shell.RunspacePool = $pool
            $null = $shell.AddScript($worker).
                AddArgument($indicator.Path).
                AddArgument($arguments).
                AddArgument($ResultAssemblyPath).
                AddArgument($ConfigLocation).
                AddArgument($startTimes).
                AddArgument($indicator.ScriptName)

            $jobs.Add([pscustomobject]@{
                Indicator = $indicator
                Shell     = $shell
                Handle    = $shell.BeginInvoke()
                Queued    = [datetime]::UtcNow
                Stopped   = $false
            })
        }

        $total = $jobs.Count
        while ($true) {
            $pending = @($jobs | Where-Object { -not $_.Handle.IsCompleted })
            if ($pending.Count -eq 0) { break }

            foreach ($job in $pending) {
                $started = $startTimes[$job.Indicator.ScriptName]
                if (-not $job.Stopped -and $started -and
                    ([datetime]::UtcNow - $started).TotalSeconds -gt $IndicatorTimeoutSeconds) {
                    Write-Warning "Timeout after ${IndicatorTimeoutSeconds}s: $($job.Indicator.ScriptName)"
                    $job.Stopped = $true
                    $null = $job.Shell.BeginStop($null, $null)
                }
            }

            $done = $total - $pending.Count
            Write-Progress -Activity 'Running Purple Knight indicators' `
                -Status "$done of $total complete - $($pending.Count) running/queued" `
                -PercentComplete (100 * $done / [Math]::Max(1, $total))
            Start-Sleep -Milliseconds 250
        }

        Write-Progress -Activity 'Running Purple Knight indicators' -Completed

        foreach ($job in $jobs) {
            $results.Add((Receive-PKJobResult -Job $job -StartTimes $startTimes))
        }
    }
    finally {
        foreach ($job in $jobs) { try { $job.Shell.Dispose() } catch { } }
        try { $pool.Close(); $pool.Dispose() } catch { }
    }

    return @($results)
}

function Receive-PKJobResult {
    <#
    .SYNOPSIS
        Converts a finished runspace job into a normalised result object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Job,
        [Parameter(Mandatory)] [hashtable] $StartTimes
    )

    $indicator = $Job.Indicator
    $started = $StartTimes[$indicator.ScriptName]
    if (-not $started) { $started = $Job.Queued }
    $duration = ([datetime]::UtcNow - $started).TotalSeconds

    $warnings = @($Job.Shell.Streams.Warning | ForEach-Object { $_.ToString() })
    $errors = @($Job.Shell.Streams.Error | ForEach-Object { $_.ToString() })

    if ($Job.Stopped) {
        return New-PKResult -Indicator $indicator -Status 'Timeout' -Score 0 `
            -ResultMessage 'The indicator exceeded the configured timeout and was cancelled.' `
            -Warnings $warnings -Errors $errors -StartTime $started -Duration $duration
    }

    try {
        $output = @($Job.Shell.EndInvoke($Job.Handle))
    }
    catch {
        return New-PKResult -Indicator $indicator -Status 'Error' -Score 0 `
            -ResultMessage $_.Exception.Message `
            -Warnings $warnings -Errors ($errors + $_.Exception.Message) -StartTime $started -Duration $duration
    }

    $payload = $output | Where-Object {
        $_ -and $_.PSObject.Properties.Name -contains 'Status' -and $_.PSObject.Properties.Name -contains 'Score'
    } | Select-Object -Last 1

    if (-not $payload) {
        $message = if ($errors) { $errors[0] } else { 'The indicator did not return a result object.' }
        return New-PKResult -Indicator $indicator -Status 'Error' -Score 0 -ResultMessage $message `
            -Warnings $warnings -Errors $errors -StartTime $started -Duration $duration
    }

    $objects = @()
    if ($payload.PSObject.Properties.Name -contains 'ResultObjects' -and $payload.ResultObjects) {
        $objects = @($payload.ResultObjects)
    }

    return New-PKResult -Indicator $indicator `
        -Status ([string]$payload.Status) `
        -Score ([int]$payload.Score) `
        -ResultMessage ([string]$payload.ResultMessage) `
        -Remediation ([string]$payload.Remediation) `
        -ResultObjects $objects `
        -Warnings $warnings -Errors $errors -StartTime $started -Duration $duration
}

function New-PKResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Indicator,
        [Parameter(Mandatory)] [string] $Status,
        [int] $Score = 100,
        [string] $ResultMessage = '',
        [string] $Remediation = '',
        [object[]] $ResultObjects = @(),
        [string[]] $Warnings = @(),
        [string[]] $Errors = @(),
        [datetime] $StartTime = [datetime]::UtcNow,
        [double] $Duration = 0
    )

    [pscustomobject]@{
        ID              = $Indicator.ID
        ShortName       = $Indicator.ShortName
        ScriptName      = $Indicator.ScriptName
        Name            = $Indicator.Name
        Category        = $Indicator.Category
        CategoryID      = $Indicator.CategoryID
        Severity        = $Indicator.Severity
        Weight          = $Indicator.Weight
        Targets         = @($Indicator.Targets)
        Environment     = (Get-PKEnvironmentName -Targets $Indicator.Targets)
        Version         = $Indicator.Version
        Status          = $Status
        Score           = $Score
        ResultMessage   = $ResultMessage
        Remediation     = $Remediation
        ObjectCount     = @($ResultObjects).Count
        ResultObjects   = @($ResultObjects)
        Warnings        = @($Warnings)
        Errors          = @($Errors)
        StartTimeUtc    = $StartTime.ToString('o')
        DurationSeconds = [Math]::Round($Duration, 2)
    }
}

function Get-PKEnvironmentName {
    <#
    .SYNOPSIS
        Maps an indicator's target codes to the environment it is reported under.
    .DESCRIPTION
        Indicators that span more than one platform are the ones Purple Knight files
        under its Hybrid category, so they are reported as their own environment rather
        than being attributed to whichever platform happens to be listed first.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string[]] $Targets)

    $known = @(@($Targets) | Where-Object { $script:PKTargetNames.ContainsKey($_) })
    if ($known.Count -gt 1) { return 'Hybrid' }
    if ($known.Count -eq 1) { return $script:PKTargetNames[$known[0]] }
    return 'Other'
}

#endregion

#region graph permissions -----------------------------------------------------

function Get-PKRequiredPermission {
    <#
    .SYNOPSIS
        Extracts the distinct Graph API permissions an indicator set needs.
    .DESCRIPTION
        Indicator metadata declares permissions as '<Source>/<Permission>', for example
        'AAD.GraphAPI/Directory.Read.All'. Only the Graph ones are relevant here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Indicators
    )

    $map = @{}
    foreach ($indicator in $Indicators) {
        foreach ($permission in @($indicator.Permissions)) {
            if ([string]::IsNullOrWhiteSpace($permission)) { continue }
            if ($permission -notmatch '^AAD\.GraphAPI/(.+)$') { continue }
            $name = $Matches[1].Trim()
            if (-not $map.ContainsKey($name)) { $map[$name] = [System.Collections.Generic.List[object]]::new() }
            $map[$name].Add($indicator)
        }
    }

    foreach ($name in ($map.Keys | Sort-Object)) {
        [pscustomobject]@{
            Permission = $name
            Indicators = @($map[$name])
            IndicatorCount = $map[$name].Count
        }
    }
}

function Get-PKGraphToken {
    <#
    .SYNOPSIS
        Acquires a Graph API token and explains clearly when it cannot.
    .DESCRIPTION
        Semperis-Lib acquires tokens with Invoke-RestMethod, which throws away the
        response body on failure, leaving only 'Response status code does not indicate
        success: 401'. Entra puts the actual reason in that body as an AADSTS code, so
        this reads it and turns the common ones into an actionable sentence.

        Returns a hashtable with Token, or Error and ErrorCode when acquisition failed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $TenantId,
        [Parameter(Mandatory)] [string] $TenantAppId,
        [Parameter(Mandatory)] [string] $TenantAppSecret,
        [string] $Scope = 'https://graph.microsoft.com/.default'
    )

    $request = @{
        Method      = 'POST'
        Uri         = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        ContentType = 'application/x-www-form-urlencoded'
        Body        = @{
            scope         = $Scope
            grant_type    = 'client_credentials'
            client_id     = $TenantAppId
            client_secret = $TenantAppSecret
        }
    }

    try {
        $response = Invoke-RestMethod @request -ErrorAction Stop
        return @{ Token = $response.access_token; Error = $null; ErrorCode = $null }
    }
    catch {
        $detail = $null
        try { $detail = $_.ErrorDetails.Message | ConvertFrom-Json } catch { }

        $code = $null
        $description = $null
        if ($detail) {
            $description = [string]$detail.error_description
            if ($description -match '(AADSTS\d+)') { $code = $Matches[1] }
        }

        $explanation = switch ($code) {
            'AADSTS7000215' { 'The client secret is wrong. Check -TenantAppSecret; make sure it is the secret VALUE, not the secret ID.' }
            'AADSTS7000222' { 'The client secret has expired. Create a new one on the app registration and use its value.' }
            'AADSTS700016'  { "No application with id $TenantAppId exists in this tenant. Check -TenantAppId and -TenantId." }
            'AADSTS700027'  { 'The client assertion was rejected. Check -TenantAppSecret.' }
            'AADSTS90002'   { "Tenant $TenantId was not found. Check -TenantId." }
            'AADSTS900023'  { "Tenant $TenantId is not a valid tenant identifier. Use the tenant GUID or its domain name." }
            'AADSTS500011'  { 'No service principal for Microsoft Graph exists in the tenant, or the scope is wrong.' }
            'AADSTS7000218' { 'The request is missing the client secret. Check -TenantAppSecret.' }
            default         { $null }
        }

        if (-not $explanation) {
            $explanation = if ($description) { ($description -split "`r?`n")[0] } else { $_.Exception.Message }
        }

        return @{ Token = $null; Error = $explanation; ErrorCode = $code }
    }
}

function Get-PKGraphPermissionContext {
    <#
    .SYNOPSIS
        Reads the Graph app roles granted to the app registration the CLI will run as.
    .DESCRIPTION
        Uses Semperis-Lib's own Graph helpers so token handling and paging behave exactly
        as they do during an assessment. Returns the granted app role IDs, the granted
        permission names, and Semperis' own privilege table so that a required permission
        can be judged satisfied by an equally or more privileged alternative.

        Reading the service principal itself needs Application.Read.All or
        Directory.Read.All. When that is missing the function reports Available = $false
        rather than throwing, so the assessment can still go ahead.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $TenantId,
        [Parameter(Mandatory)] [string] $TenantAppId,
        [Parameter(Mandatory)] [string] $TenantAppSecret
    )

    $result = [pscustomobject]@{
        Available          = $false
        Authenticated      = $false
        Reason             = $null
        ErrorCode          = $null
        GrantedRoleIds     = @()
        GrantedPermissions = @()
        PrivilegeTable     = @{}
        GraphAppRoles      = @{}
    }

    $token = $null
    try {
        Import-Module Semperis-Lib -ErrorAction Stop
        $lib = Get-Module Semperis-Lib

        $acquired = Get-PKGraphToken -TenantId $TenantId -TenantAppId $TenantAppId -TenantAppSecret $TenantAppSecret
        if (-not $acquired.Token) {
            $result.ErrorCode = $acquired.ErrorCode
            throw $acquired.Error
        }
        $token = $acquired.Token
        $result.Authenticated = $true

        $principal = Invoke-GraphApiRequest -AccessToken $token `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/?`$filter=appId eq '$TenantAppId'"
        $principalId = @($principal.value)[0].id
        if (-not $principalId) { throw "No service principal was found for application $TenantAppId in this tenant." }

        $assignments = Invoke-GraphApiRequest -AccessToken $token `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments"
        $graphAssignments = @($assignments.value | Where-Object { $_.resourceDisplayName -eq 'Microsoft Graph' })
        $result.GrantedRoleIds = @($graphAssignments.appRoleId | Where-Object { $_ })

        # Translate the granted role id GUIDs into permission names using Graph's own catalogue.
        $graphSp = Invoke-GraphApiRequest -AccessToken $token `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles"
        $roles = @(@($graphSp.value)[0].appRoles)

        $byId = @{}
        $byValue = @{}
        foreach ($role in $roles) {
            $byId[[string]$role.id] = [string]$role.value
            $byValue[[string]$role.value] = [string]$role.id
        }
        $result.GraphAppRoles = $byValue
        $result.GrantedPermissions = @($result.GrantedRoleIds |
            ForEach-Object { if ($byId.ContainsKey([string]$_)) { $byId[[string]$_] } } |
            Sort-Object -Unique)

        if ($lib) { $result.PrivilegeTable = & $lib { $DefinedPermissions } }
        $result.Available = $true
    }
    catch {
        $result.Reason = $_.Exception.Message
    }

    return $result
}

function Test-PKPermissionGranted {
    <#
    .SYNOPSIS
        Decides whether a required Graph permission is covered by what has been granted.
    .DESCRIPTION
        A permission counts as granted when it was assigned directly, or when a more
        privileged alternative was assigned. The alternatives come from Semperis' own
        privilege table: any entry that lists the required permission's app role id also
        lists the other role ids that satisfy the same need, so granting any of them is
        enough - which is exactly the judgement Purple Knight makes when it handles a 403.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Permission,
        [Parameter(Mandatory)] $Context
    )

    if ($Context.GrantedPermissions -contains $Permission) { return $true }

    $roleId = if ($Context.GraphAppRoles.ContainsKey($Permission)) { [string]$Context.GraphAppRoles[$Permission] } else { $null }
    if (-not $roleId) { return $false }
    if ($Context.GrantedRoleIds -contains $roleId) { return $true }

    foreach ($entry in $Context.PrivilegeTable.Values) {
        $alternatives = @($entry.appRoleIds | ForEach-Object { [string]$_ })
        if ($alternatives -notcontains $roleId) { continue }
        foreach ($granted in $Context.GrantedRoleIds) {
            if ($alternatives -contains [string]$granted) { return $true }
        }
    }

    return $false
}

function Get-PKPermissionReport {
    <#
    .SYNOPSIS
        Compares the Graph permissions an indicator set needs against those granted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Indicators,
        [Parameter(Mandatory)] $Context
    )

    $required = @(Get-PKRequiredPermission -Indicators $Indicators)

    # Read optional fields defensively: callers construct the context themselves, and a
    # missing property should not take the whole report down.
    $prop = {
        param($object, $name, $default)
        if ($object -and $object.PSObject.Properties.Name -contains $name) { $object.$name } else { $default }
    }

    $available = [bool](& $prop $Context 'Available' $false)

    $permissions = foreach ($item in $required) {
        $granted = if ($available) { Test-PKPermissionGranted -Permission $item.Permission -Context $Context } else { $null }
        [pscustomobject]@{
            Permission     = $item.Permission
            Granted        = $granted
            IndicatorCount = $item.IndicatorCount
            Indicators     = @($item.Indicators | ForEach-Object { $_.ScriptName } | Sort-Object)
        }
    }

    $missing = @($permissions | Where-Object { $_.Granted -eq $false })
    $blocked = @($missing | ForEach-Object { $_.Indicators } | Sort-Object -Unique)

    [pscustomobject]@{
        Available          = $available
        Authenticated      = [bool](& $prop $Context 'Authenticated' $false)
        Reason             = (& $prop $Context 'Reason' $null)
        ErrorCode          = (& $prop $Context 'ErrorCode' $null)
        GrantedPermissions = @(& $prop $Context 'GrantedPermissions' @())
        Permissions        = @($permissions)
        Missing            = @($missing)
        BlockedIndicators  = $blocked
    }
}

function Write-PKPermissionReport {
    <#
    .SYNOPSIS
        Prints the pre-flight Graph permission check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Report,
        [switch] $Detailed
    )

    Write-Host ''
    Write-Host 'Graph API permission check' -ForegroundColor Cyan

    if (-not $Report.Available) {
        if (-not $Report.Authenticated) {
            # Sign-in failed outright, so nothing will run. Say so plainly.
            $code = if ($Report.ErrorCode) { " [$($Report.ErrorCode)]" } else { '' }
            Write-Host "  Sign-in to the tenant failed$code" -ForegroundColor Red
            Write-Host "  $($Report.Reason)" -ForegroundColor Red
            Write-Host '  Every Entra ID indicator will fail until this is fixed.' -ForegroundColor DarkGray
        }
        else {
            Write-Host "  Signed in, but the app registration's granted permissions could not be read: $($Report.Reason)" -ForegroundColor DarkYellow
            Write-Host '  Reading them needs Application.Read.All or Directory.Read.All. Indicators are still run, and any that' -ForegroundColor DarkGray
            Write-Host '  lack permission report "Insufficient permissions" with the exact permission they need.' -ForegroundColor DarkGray
        }
        Write-Host ''
        return
    }

    $granted = @($Report.Permissions | Where-Object { $_.Granted })
    Write-Host ("  {0} of {1} required permissions are granted." -f $granted.Count, $Report.Permissions.Count) -ForegroundColor Gray

    if ($Report.Missing.Count -eq 0) {
        Write-Host '  All required Graph permissions are present.' -ForegroundColor Green
        Write-Host ''
        return
    }

    Write-Host ("  {0} permission(s) missing, blocking {1} indicator(s):" -f $Report.Missing.Count, $Report.BlockedIndicators.Count) -ForegroundColor Yellow
    foreach ($item in $Report.Missing | Sort-Object IndicatorCount -Descending) {
        Write-Host ('    {0,-45} {1} indicator(s)' -f $item.Permission, $item.IndicatorCount) -ForegroundColor Yellow
        if ($Detailed) {
            foreach ($name in $item.Indicators) { Write-Host "        $name" -ForegroundColor DarkGray }
        }
    }
    Write-Host '  Grant these to the app registration, or exclude the affected indicators, to get a complete assessment.' -ForegroundColor DarkGray
    Write-Host ''
}

#endregion

#region scoring ---------------------------------------------------------------

function Get-PKWeightedScore {
    <#
    .SYNOPSIS
        Core of Purple Knight's posture score: turns a set of severity/score pairs into
        a 0..100 score.
    .DESCRIPTION
        Mirrors ReportGeneration.ResultsStore.RiskAssessment.CalculateTotalScore and
        CalculateSITotalImpactBySeverity.

        Indicators are grouped by severity. Each indicator has an exposure of
        (100 - indicatorScore) / 100, and contributes a multiplicative residual of

            1 - basePenalty(severity) * exposure

        The residuals for a severity are multiplied together, so 1 means "nothing found"
        and 0 means "maximum exposure". The complement of that product is scaled by the
        severity weight (x100) to give a penalty, and the final score is 100 minus the
        sum of the penalties, floored and clamped to 0..100.

        Because the residuals compound rather than add, each additional finding of the
        same severity moves the score less than the previous one - the "decay effect"
        described in the report - and an indicator that scored 100 is entirely neutral.

        The severity constants and the flooring behaviour were verified against
        ReportGeneration.dll over randomised inputs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results
    )

    $penalty = 0.0

    foreach ($severity in $script:PKBasePenalty.Keys) {
        $basePenalty = [double]$script:PKBasePenalty[$severity]
        $severityWeight = [double]$script:PKSeverityWeight[$severity]
        if ($basePenalty -eq 0 -or $severityWeight -eq 0) { continue }

        $group = @($Results | Where-Object { $_.Severity -eq $severity })
        if ($group.Count -eq 0) { continue }

        $residual = 1.0
        foreach ($item in $group) {
            $exposure = (100.0 - [double]$item.Score) / 100.0
            if ($exposure -le 0) { continue }
            $residual *= (1.0 - $basePenalty * $exposure)
        }
        $penalty += (1.0 - $residual) * $severityWeight * 100.0
    }

    $score = [Math]::Floor(100.0 - $penalty)
    if ($score -lt 0) { $score = 0 }
    if ($score -gt 100) { $score = 100 }
    return [int]$score
}

function Get-PKPostureScore {
    <#
    .SYNOPSIS
        Security posture score for a set of indicator results.
    .DESCRIPTION
        Only indicators that actually produced an assessment (Pass or Failed) take part,
        which matches the desktop application: indicators that were not selected or that
        could not run have no effect on the score.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results
    )

    $evaluated = @($Results | Where-Object { $_.Status -in @('Pass', 'Failed') })
    if ($evaluated.Count -eq 0) { return 100 }

    return Get-PKWeightedScore -Results $evaluated
}

function Get-PKGrade {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [int] $Score)

    foreach ($entry in $script:PKGradeTable) {
        if ($Score -ge $entry.Min) { return $entry.Grade }
    }
    return 'F'
}

function Get-PKSummary {
    <#
    .SYNOPSIS
        Aggregates results into an overall summary plus one section per environment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results
    )

    $environments = foreach ($group in ($Results | Group-Object Environment | Sort-Object Name)) {
        # An environment where nothing could be evaluated has no score, rather than a perfect one.
        $evaluated = @($group.Group | Where-Object Status -in @('Pass', 'Failed'))
        $score = if ($evaluated.Count -eq 0) { $null } else { Get-PKPostureScore -Results $group.Group }
        [pscustomobject]@{
            Environment   = $group.Name
            Score         = $score
            Grade         = if ($null -eq $score) { 'n/a' } else { Get-PKGrade -Score $score }
            Total         = $group.Count
            Assessed      = $evaluated.Count
            Coverage      = if ($group.Count -eq 0) { 0 } else { [Math]::Round(100 * $evaluated.Count / $group.Count) }
            Failed        = @($group.Group | Where-Object Status -eq 'Failed').Count
            Passed        = @($group.Group | Where-Object Status -eq 'Pass').Count
            Errors        = @($group.Group | Where-Object Status -in @('Error', 'Timeout')).Count
            NotRelevant   = @($group.Group | Where-Object Status -eq 'NotRelevant').Count
            Skipped       = @($group.Group | Where-Object Status -eq 'Skipped').Count
            BySeverity    = Get-PKSeverityBreakdown -Results $group.Group
        }
    }

    [pscustomobject]@{
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        Total          = $Results.Count
        Failed         = @($Results | Where-Object Status -eq 'Failed').Count
        Passed         = @($Results | Where-Object Status -eq 'Pass').Count
        Errors         = @($Results | Where-Object Status -in @('Error', 'Timeout')).Count
        NotRelevant    = @($Results | Where-Object Status -eq 'NotRelevant').Count
        Skipped        = @($Results | Where-Object Status -eq 'Skipped').Count
        BySeverity     = Get-PKSeverityBreakdown -Results $Results
        Environments   = @($environments)
    }
}

function Get-PKSeverityBreakdown {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results)

    $failed = @($Results | Where-Object Status -eq 'Failed')
    $breakdown = [ordered]@{}
    foreach ($severity in ($script:PKSeverityOrder.GetEnumerator() | Sort-Object Value | ForEach-Object Key)) {
        $breakdown[$severity] = @($failed | Where-Object Severity -eq $severity).Count
    }
    return [pscustomobject]$breakdown
}

function Get-PKSortedResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results)

    $statusRank = @{ Failed = 0; Error = 1; Timeout = 1; Pass = 2; NotRelevant = 3; Skipped = 4 }
    return @($Results | Sort-Object `
        @{ Expression = { if ($statusRank.ContainsKey($_.Status)) { $statusRank[$_.Status] } else { 9 } } },
        @{ Expression = { if ($script:PKSeverityOrder.ContainsKey($_.Severity)) { $script:PKSeverityOrder[$_.Severity] } else { 9 } } },
        @{ Expression = { $_.Score } },
        @{ Expression = { $_.Name } })
}

#endregion

#region reporting -------------------------------------------------------------

function Write-PKConsoleReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results,
        [Parameter(Mandatory)] $Summary
    )

    $colors = @{
        Critical = 'Red'; High = 'Red'; Medium = 'Yellow'
        Low = 'DarkYellow'; Warning = 'DarkYellow'; Informational = 'Gray'
    }

    Write-Host ''
    Write-Host '=================== Purple Knight - security posture ===================' -ForegroundColor Cyan
    foreach ($environment in $Summary.Environments) {
        $color = if ($null -eq $environment.Score) { 'DarkGray' }
                 elseif ($environment.Score -ge 90) { 'Green' }
                 elseif ($environment.Score -ge 75) { 'Yellow' }
                 else { 'Red' }
        $scoreText = if ($null -eq $environment.Score) { 'n/a' } else { '{0}%' -f $environment.Score }
        Write-Host ('  {0,-18} {1,4}  ({2,-3})  assessed {3,3}/{4,-3}  failed {5,-4} error {6,-4} skipped {7}' -f `
            $environment.Environment, $scoreText, $environment.Grade, $environment.Assessed, $environment.Total,
            $environment.Failed, $environment.Errors, $environment.Skipped) -ForegroundColor $color
    }

    # A score built from a fraction of the indicators is optimistic, because the ones that
    # could not run are excluded rather than counted against the score. Say so.
    $incomplete = @($Summary.Environments | Where-Object { $_.Assessed -gt 0 -and $_.Assessed -lt $_.Total })
    foreach ($environment in $incomplete) {
        Write-Host ('  ! {0}: only {1}% of indicators were assessed, so this score is optimistic.' -f `
            $environment.Environment, $environment.Coverage) -ForegroundColor DarkYellow
    }

    Write-Host ''
    Write-Host 'Indicators of exposure found, by severity:' -ForegroundColor Cyan
    foreach ($property in $Summary.BySeverity.PSObject.Properties) {
        if ($property.Value -eq 0) { continue }
        $color = if ($colors.ContainsKey($property.Name)) { $colors[$property.Name] } else { 'Gray' }
        Write-Host ('  {0,-14} {1}' -f $property.Name, $property.Value) -ForegroundColor $color
    }

    $failed = @(Get-PKSortedResult -Results @($Results | Where-Object Status -eq 'Failed'))
    if ($failed.Count -gt 0) {
        Write-Host ''
        Write-Host 'Findings:' -ForegroundColor Cyan
        $failed | Format-Table -AutoSize -Property `
            @{ N = 'Severity'; E = { $_.Severity } },
            @{ N = 'Env'; E = { $_.Environment } },
            @{ N = 'Indicator'; E = { $_.Name } },
            @{ N = 'Score'; E = { $_.Score } },
            @{ N = 'Objects'; E = { $_.ObjectCount } } | Out-Host
    }

    $broken = @($Results | Where-Object Status -in @('Error', 'Timeout'))
    if ($broken.Count -gt 0) {
        # Missing Graph permissions are the most common and most fixable cause, so they
        # get their own section with the exact permission names Semperis reports.
        $denied = @($broken | Where-Object { $_.ResultMessage -match 'Insufficient permissions' -or $_.Remediation -match 'Graph API permission' })
        $other  = @($broken | Where-Object { $denied -notcontains $_ })

        if ($denied.Count -gt 0) {
            Write-Host ''
            Write-Host "Indicators blocked by insufficient Graph API permissions: $($denied.Count)" -ForegroundColor Yellow
            $needed = @($denied |
                ForEach-Object { if ($_.Remediation -match 'permission\(s\):\s*(.+)$') { $Matches[1] -split ';' } } |
                ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)
            foreach ($permission in $needed) {
                $count = @($denied | Where-Object { $_.Remediation -like "*$permission*" }).Count
                Write-Host ('  {0,-45} blocks {1} indicator(s)' -f $permission, $count) -ForegroundColor Yellow
            }
            Write-Host '  Grant these to the Entra ID app registration and re-run.' -ForegroundColor DarkGray
        }

        if ($other.Count -gt 0) {
            Write-Host ''
            Write-Host "Indicators that could not run: $($other.Count)" -ForegroundColor DarkYellow
            foreach ($item in $other | Select-Object -First 15) {
                Write-Host ("  {0}: {1}" -f $item.ScriptName, $item.ResultMessage) -ForegroundColor DarkGray
            }
            if ($other.Count -gt 15) { Write-Host "  ... and $($other.Count - 15) more, see the JSON or CSV report." -ForegroundColor DarkGray }
        }
    }

    # Skipped indicators never ran at all. Without this section a run where everything
    # was skipped prints an empty report and looks like a success.
    $skipped = @($Results | Where-Object Status -eq 'Skipped')
    if ($skipped.Count -gt 0) {
        Write-Host ''
        Write-Host "Indicators skipped because required input was missing: $($skipped.Count)" -ForegroundColor Yellow
        foreach ($group in ($skipped | Group-Object ResultMessage | Sort-Object Count -Descending)) {
            Write-Host ('  {0,-4} {1}' -f $group.Count, $group.Name) -ForegroundColor Yellow
            $sample = @($group.Group | Select-Object -First 3 -ExpandProperty ScriptName)
            Write-Host ('       e.g. {0}{1}' -f ($sample -join ', '), $(if ($group.Count -gt 3) { ', ...' } else { '' })) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
}

function Export-PKJsonReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results,
        [Parameter(Mandatory)] $Summary,
        [Parameter(Mandatory)] $RunInfo,
        [Parameter(Mandatory)] [string] $Path,
        $PermissionReport
    )

    $payload = [ordered]@{
        Run        = $RunInfo
        Summary    = $Summary
        Indicators = @(Get-PKSortedResult -Results $Results)
    }

    if ($PermissionReport) {
        $payload['PermissionCheck'] = [pscustomobject]@{
            Authenticated      = $PermissionReport.Authenticated
            Available          = $PermissionReport.Available
            Reason             = $PermissionReport.Reason
            GrantedPermissions = @($PermissionReport.GrantedPermissions)
            MissingPermissions = @($PermissionReport.Missing | Select-Object Permission, IndicatorCount, Indicators)
            BlockedIndicators  = @($PermissionReport.BlockedIndicators)
        }
    }

    [pscustomobject]$payload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8

    return $Path
}

function Export-PKCsvReport {
    <#
    .SYNOPSIS
        Writes a summary CSV plus one CSV per failed indicator holding the affected objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results,
        [Parameter(Mandatory)] [string] $Path,
        [string] $DetailDirectory
    )

    Get-PKSortedResult -Results $Results |
        Select-Object ID, ShortName, ScriptName, Name, Category, Environment, Severity,
            Status, Score, ObjectCount, ResultMessage, Remediation, DurationSeconds, Version |
        Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8

    if ($DetailDirectory) {
        $null = New-Item -ItemType Directory -Force -Path $DetailDirectory
        foreach ($result in $Results | Where-Object { $_.ObjectCount -gt 0 }) {
            $file = Join-Path $DetailDirectory "$($result.ScriptName).csv"
            try {
                $result.ResultObjects | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8
            }
            catch {
                Write-Verbose "Could not export objects for $($result.ScriptName): $($_.Exception.Message)"
            }
        }
    }

    return $Path
}

function Export-PKHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results,
        [Parameter(Mandatory)] $Summary,
        [Parameter(Mandatory)] $RunInfo,
        [Parameter(Mandatory)] [string] $Path
    )

    $enc = { param($value) [System.Net.WebUtility]::HtmlEncode([string]$value) }

    $cards = foreach ($environment in $Summary.Environments) {
        $class = if ($null -eq $environment.Score) { 'none' }
                 elseif ($environment.Score -ge 90) { 'good' }
                 elseif ($environment.Score -ge 75) { 'warn' }
                 else { 'bad' }
        $scoreHtml = if ($null -eq $environment.Score) { 'n/a' } else { "$($environment.Score)<span>%</span>" }
        @"
  <div class="card $class">
    <div class="score">$scoreHtml</div>
    <div class="grade">$(& $enc $environment.Grade)</div>
    <div class="env">$(& $enc $environment.Environment)</div>
    <div class="counts">assessed $($environment.Assessed)/$($environment.Total) &middot; $($environment.Failed) found &middot; $($environment.Errors) errors &middot; $($environment.Skipped) skipped</div>
    $(if ($environment.Assessed -gt 0 -and $environment.Assessed -lt $environment.Total) { "<div class=`"caveat`">Only $($environment.Coverage)% assessed - this score is optimistic</div>" })
  </div>
"@
    }

    $rows = foreach ($result in Get-PKSortedResult -Results $Results) {
        $objectTable = ''
        if ($result.ObjectCount -gt 0) {
            $columns = @($result.ResultObjects[0].PSObject.Properties.Name)
            $header = ($columns | ForEach-Object { "<th>$(& $enc $_)</th>" }) -join ''
            $body = foreach ($object in $result.ResultObjects | Select-Object -First 200) {
                $cells = ($columns | ForEach-Object { "<td>$(& $enc $object.$_)</td>" }) -join ''
                "<tr>$cells</tr>"
            }
            $more = if ($result.ObjectCount -gt 200) { "<p class='more'>Showing 200 of $($result.ObjectCount) objects - see the CSV export for the full list.</p>" } else { '' }
            $objectTable = "<table class='objects'><thead><tr>$header</tr></thead><tbody>$($body -join '')</tbody></table>$more"
        }

        $detail = "<div class='detail'><p><strong>Result:</strong> $(& $enc $result.ResultMessage)</p>"
        if ($result.Remediation) { $detail += "<p><strong>Remediation:</strong> $(& $enc $result.Remediation)</p>" }
        $detail += "$objectTable</div>"

        @"
  <tr class="status-$($result.Status.ToLower())" onclick="toggle(this)">
    <td><span class="sev sev-$($result.Severity.ToLower())">$(& $enc $result.Severity)</span></td>
    <td>$(& $enc $result.Status)</td>
    <td>$(& $enc $result.Environment)</td>
    <td>$(& $enc $result.Category)</td>
    <td class="name">$(& $enc $result.Name)<br><span class="sn">$(& $enc $result.ScriptName)</span></td>
    <td class="num">$($result.Score)</td>
    <td class="num">$($result.ObjectCount)</td>
  </tr>
  <tr class="details"><td colspan="7">$detail</td></tr>
"@
    }

    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Purple Knight CLI report</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f5f9;color:#1b1b2b}
 header{background:#3c1a5b;color:#fff;padding:22px 32px}
 header h1{margin:0;font-size:22px}
 header p{margin:6px 0 0;opacity:.8;font-size:13px}
 .cards{display:flex;flex-wrap:wrap;gap:16px;padding:24px 32px}
 .card{background:#fff;border-radius:10px;padding:18px 24px;min-width:210px;box-shadow:0 1px 4px rgba(0,0,0,.12);border-top:4px solid #999}
 .card.good{border-top-color:#1b9a00}.card.warn{border-top-color:#ba8808}.card.bad{border-top-color:#cc021b}.card.none{border-top-color:#8a8a8a}
 .caveat{margin-top:6px;font-size:11px;color:#ba8808;font-weight:600}
 .card .score{font-size:40px;font-weight:600;line-height:1}
 .card .score span{font-size:18px;opacity:.6}
 .card .grade{font-size:14px;font-weight:600;opacity:.7}
 .card .env{margin-top:6px;font-size:15px;font-weight:600}
 .card .counts{margin-top:4px;font-size:12px;opacity:.7}
 table.main{width:calc(100% - 64px);margin:0 32px 40px;border-collapse:collapse;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.12)}
 table.main th{background:#eceef5;text-align:left;padding:10px;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
 table.main td{padding:10px;border-top:1px solid #e6e8f0;font-size:14px;vertical-align:top}
 table.main tr:not(.details){cursor:pointer}
 table.main tr.status-failed .name{font-weight:600}
 .num{text-align:right}
 .sn{font-size:11px;opacity:.55}
 .sev{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
 .sev-critical{background:#cc021b}.sev-high{background:#e75402}.sev-medium{background:#ba8808}
 .sev-low{background:#4a90d9}.sev-warning{background:#8a8a8a}.sev-informational{background:#b0b0b0}
 tr.details{display:none;background:#fafbff}
 tr.details.open{display:table-row}
 .detail p{margin:4px 0}
 table.objects{border-collapse:collapse;margin-top:10px;width:100%}
 table.objects th,table.objects td{border:1px solid #dfe2ec;padding:4px 8px;font-size:12px;text-align:left}
 table.objects th{background:#f0f2f8}
 .more{font-size:12px;opacity:.7}
</style>
<script>
 function toggle(row){var d=row.nextElementSibling;if(d&&d.classList.contains('details')){d.classList.toggle('open');}}
</script>
</head><body>
<header>
 <h1>Purple Knight - command line assessment</h1>
 <p>Generated $(& $enc $RunInfo.GeneratedAtUtc) UTC on $(& $enc $RunInfo.ComputerName) &middot; $($Summary.Total) indicators &middot; $($Summary.Failed) indicators of exposure found</p>
</header>
<div class="cards">
$($cards -join "`n")
</div>
<table class="main">
 <thead><tr><th>Severity</th><th>Status</th><th>Environment</th><th>Category</th><th>Indicator</th><th>Score</th><th>Objects</th></tr></thead>
 <tbody>
$($rows -join "`n")
 </tbody>
</table>
</body></html>
"@

    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
    return $Path
}

#endregion

Export-ModuleMember -Function @(
    'Resolve-PKInstallPath'
    'Get-PKResultTypeAssembly'
    'Initialize-PKResultType'
    'Get-PKCategoryMap'
    'Get-PKIndicatorCatalog'
    'Select-PKIndicator'
    'ConvertTo-PKTargetCode'
    'Invoke-PKIndicatorSet'
    'Get-PKRequiredPermission'
    'Get-PKGraphToken'
    'Get-PKGraphPermissionContext'
    'Get-PKPermissionReport'
    'Write-PKPermissionReport'
    'Get-PKPostureScore'
    'Get-PKWeightedScore'
    'Get-PKGrade'
    'Get-PKSummary'
    'Get-PKSortedResult'
    'Write-PKConsoleReport'
    'Export-PKJsonReport'
    'Export-PKCsvReport'
    'Export-PKHtmlReport'
)
