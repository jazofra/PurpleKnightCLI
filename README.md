# Purple Knight CLI

A head-less runner for Purple Knight Community. It executes exactly the same security
indicators as the desktop application, from the command line, and produces console,
JSON, CSV and HTML reports.

Purple Knight Community ships only as a WPF desktop application (`PurpleKnight.exe`)
with no command line switches. Its indicators, however, are ordinary PowerShell scripts
under `Scripts\Semperis.SI.*\<version>\<name>.ps1` that the UI runs in a runspace pool
with a small set of connection parameters. This CLI does the same thing:

* the original indicator scripts and the `Semperis-Lib` helper module are loaded and
  executed **unmodified**, so findings are identical to the UI's;
* indicator discovery uses each script's own `-Metadata` switch, so new or updated
  indicators are picked up automatically after an application update;
* the security posture score and letter grade use Purple Knight's own algorithm and
  severity constants, verified to be bit-exact against `ReportGeneration.dll`.

## Requirements

* PowerShell 7 (`pwsh`). The desktop application hosts PowerShell 7.4, so `pwsh` is the
  matching runtime. Windows PowerShell 5.1 is not supported.
* Run on a machine that can reach the environments being assessed, under an account with
  the permissions Purple Knight normally needs (a plain domain user is enough for most
  AD indicators; a few need to read `SYSVOL` or query domain controllers remotely).
* For Entra ID, an app registration with the permissions listed by
  `-ListIndicators` (`Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`,
  `RoleManagement.Read.Directory`, ...) and a client secret.

## Layout

```
CLI\
  Invoke-PurpleKnight.ps1    entry point
  PurpleKnightCli.psm1       discovery, execution, scoring and reporting
  lib\                       Semperis.PSSecurityIndicatorResult.dll (result type)
  cache\                     cached indicator catalog, rebuilt automatically
  examples\                  sample config file and scheduled-task wrapper
```

## Quick start

List everything that can be run:

```powershell
pwsh -File ".\Invoke-PurpleKnight.ps1" -ListIndicators
```

Assess Active Directory using the current machine's forest:

```powershell
pwsh -File ".\Invoke-PurpleKnight.ps1" -Target AD
```

Assess Entra ID:

```powershell
pwsh -File ".\Invoke-PurpleKnight.ps1" -Target EntraID `
     -TenantId <guid> -TenantAppId <guid> -TenantAppSecret <secret>
```

Assess everything you have credentials for, into a specific folder:

```powershell
pwsh -File ".\Invoke-PurpleKnight.ps1" -ConfigFile .\examples\pk-config.example.json `
     -OutputPath D:\Reports\PK
```

Run a subset:

```powershell
pwsh -File ".\Invoke-PurpleKnight.ps1" -Target AD -Severity Critical -OutputFormat Console
pwsh -File ".\Invoke-PurpleKnight.ps1" -Target AD -Category 'Kerberos*','*Delegation*'
pwsh -File ".\Invoke-PurpleKnight.ps1" -Indicator 'ESC*','ZeroLogonPK'
```

Get objects back on the pipeline instead of reading a report (run from inside `pwsh`):

```powershell
$run = & '.\Invoke-PurpleKnight.ps1' -Target AD -OutputFormat None -PassThru
$run.Summary.Environments
$run.Indicators | Where-Object Status -eq 'Failed' | Select-Object Severity, Name, ObjectCount
```

Full help:

```powershell
Get-Help .\Invoke-PurpleKnight.ps1 -Full
```

## Parameters

| Parameter | Description |
| --- | --- |
| `-InstallPath` | Purple Knight directory. Defaults to the parent of this folder, then `$env:PURPLEKNIGHT_HOME`, then the current directory. |
| `-ConfigFile` | JSON file holding any of these parameters. Command line values win. |
| `-ListIndicators` | Print the catalog and exit. |
| `-Target` | `AD`, `EntraID` (aliases `AAD`, `Entra`), `Okta`. Inferred from the supplied credentials when omitted. |
| `-Category` | Category names, wildcards allowed. |
| `-Severity` | `Critical`, `High`, `Medium`, `Low`, `Warning`, `Informational`. |
| `-Indicator` / `-ExcludeIndicator` | Match on script name, short name (`SI000146`), display name, numeric ID or UUID. Wildcards allowed. |
| `-IncludeUnselected` | Also run indicators Purple Knight does not select by default. |
| `-ForestName` / `-DomainNames` | AD scope. Auto-detected from the current machine when omitted. |
| `-DomainCredential` | Alternate LDAP credentials, passed to the indicators via the `IOE_FOREST_CREDENTIALS` variable that `Semperis-Lib` reads. |
| `-TenantId` / `-TenantAppId` / `-TenantAppSecret` | Entra ID app registration. |
| `-OktaDomain` / `-OktaApiToken` | Okta connection. |
| `-AttackWindowDays` | Window for the "recent change" indicators. Default 30, matching `Settings.xml`. |
| `-ThrottleLimit` | Concurrent indicators. `0` (default) uses the processor count, like the UI. |
| `-IndicatorTimeoutSeconds` | Per indicator timeout, default 900. Indicators still running are cancelled and reported as `Timeout`. |
| `-OutputPath` | Report directory. Defaults to `<InstallPath>\Output\CLI-<timestamp>`. |
| `-OutputFormat` | Any of `Console`, `Json`, `Csv`, `Html`, `None`. |
| `-FailOn` | Lowest severity of finding that makes the script exit with code 2. `None` (default), `Any`, or a severity name. |
| `-SkipPermissionCheck` | Skip the pre-flight Graph permission check. |
| `-CheckPermissionsOnly` | Run the permission check, list what is missing and which indicators it blocks, then exit without assessing. |
| `-PassThru` | Emit the run, summary, permission check and indicator objects on the pipeline. |
| `-RefreshCatalog` | Rebuild the cached catalog. Only needed if you edit indicator scripts in place. |

Secrets can also be supplied through environment variables, which keeps them out of the
command line and console history: `PK_TENANT_ID`, `PK_TENANT_APP_ID`,
`PK_TENANT_APP_SECRET`, `PK_OKTA_DOMAIN`, `PK_OKTA_API_TOKEN`.

When passing several values to a list parameter, use `pwsh -Command` rather than
`pwsh -File`: with `-File`, PowerShell treats everything after the parameter name as one
literal string, so `-Severity Critical,High` would arrive as the single value
`Critical,High` and match nothing.

```powershell
pwsh -NoProfile -Command "& '.\Invoke-PurpleKnight.ps1' -Target AD -Severity Critical,High"
```

## Output

`-OutputPath` receives:

| File | Contents |
| --- | --- |
| `purple-knight-report.html` | Self-contained report: posture score card per environment, sortable finding list, click a row to expand the affected objects. |
| `purple-knight-results.json` | Everything, including every affected object. The natural input for a SIEM or a diffing script. |
| `purple-knight-summary.csv` | One row per indicator. |
| `details\<indicator>.csv` | Affected objects for each indicator that found something. |

## Partial Graph permissions

You will almost always have some Graph permissions and not others, so the CLI is explicit
about it rather than silently under-reporting.

**Before the run**, it checks the app registration's granted Graph app roles against the
permissions the selected indicators declare, and prints what is missing and how many
indicators each missing permission blocks:

```
Graph API permission check
  7 of 18 required permissions are granted.
  11 permission(s) missing, blocking 53 indicator(s):
    Policy.Read.All                               23 indicator(s)
    AuditLog.Read.All                             18 indicator(s)
    ...
```

A permission counts as granted if it was assigned directly **or** if a more privileged
alternative was assigned — `Directory.Read.All`, for example, satisfies `User.Read.All`,
`Device.Read.All`, `GroupMember.Read.All`, `Organization.Read.All`,
`AdministrativeUnit.Read.All` and `RoleManagement.Read.Directory`. The equivalences come
from Semperis' own privilege table in `Semperis-Lib`, so the verdict matches Purple
Knight's.

Check without assessing anything:

```powershell
pwsh -File .\Invoke-PurpleKnight.ps1 -Target EntraID -TenantId <guid> -TenantAppId <guid> `
     -TenantAppSecret <secret> -CheckPermissionsOnly
```

This exits `3` if permissions are missing, `1` if sign-in failed, `0` if everything needed
is granted — so a pipeline can gate on it. Use `-SkipPermissionCheck` to bypass.

Reading the granted permissions itself needs `Application.Read.All` or
`Directory.Read.All`. If that is missing the check says so and the assessment still runs;
nothing is blocked by the check failing.

### Sign-in failures

If sign-in fails, the check reports the underlying Entra `AADSTS` code and what to do
about it, instead of the bare `401 (Unauthorized)` that the raw token call produces:

```
Graph API permission check
  Sign-in to the tenant failed [AADSTS7000215]
  The client secret is wrong. Check -TenantAppSecret; make sure it is the secret VALUE, not the secret ID.
```

| Code | Meaning |
| --- | --- |
| `AADSTS7000215` | Wrong client secret. Note this means the tenant and app id *are* valid. |
| `AADSTS7000222` | The client secret has expired — create a new one. |
| `AADSTS700016` | No app with that id in this tenant. Check `-TenantAppId` / `-TenantId`. |
| `AADSTS90002` | Tenant not found. Check `-TenantId`. |
| `AADSTS900023` | `-TenantId` is not a valid tenant identifier; use the GUID or domain name. |

Because every Entra ID indicator would fail identically, the CLI stops instead of
collecting the same error dozens of times. If the run also covers AD or Okta it drops
only the Entra indicators and carries on. `-SkipPermissionCheck` forces it to run anyway.

The most common cause is pasting the secret **ID** from the portal instead of the secret
**value** — the value is only shown once, immediately after you create it.

**After the run**, indicators that hit a 403 are reported separately from other failures,
with the exact permission Semperis says they need:

```
Indicators blocked by insufficient Graph API permissions: 12
  AuditLog.Read.All                             blocks 8 indicator(s)
  Reports.Read.All                              blocks 4 indicator(s)
```

Those indicators get status `Error`, so they are excluded from the posture score rather
than counted as passes. That is what Purple Knight itself does, but it has an important
consequence: **a score built from partial permissions is optimistic**, because a check
that could not run cannot lower the score. The console and HTML reports therefore show
how many indicators were actually assessed and flag any environment with incomplete
coverage:

```
  Entra ID            89%  (C+ )  assessed 24/70   failed 6    error 46   skipped 0
  ! Entra ID: only 34% of indicators were assessed, so this score is optimistic.
```

Treat the score as comparable over time only when coverage is the same. The JSON report
carries the whole picture under `PermissionCheck`, each environment has `Assessed`,
`Total` and `Coverage`, and the per-indicator `Remediation` field holds the permission
names; the summary CSV includes `Remediation` too.

## Statuses

| Status | Meaning |
| --- | --- |
| `Pass` | The indicator ran and found nothing. |
| `Failed` | An indicator of exposure was found. |
| `NotRelevant` | The indicator does not apply to this environment. |
| `Error` | The indicator ran but could not complete, e.g. the domain was unreachable or permissions were missing. |
| `Timeout` | Cancelled after `-IndicatorTimeoutSeconds`. |
| `Skipped` | The connection details the indicator needs were not supplied. |

Only `Pass` and `Failed` contribute to the posture score, which matches the desktop
application: indicators that were not selected or that could not run have no effect. An
environment where nothing at all could be evaluated is reported as `n/a` rather than as
a perfect score.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ran successfully; no finding at or above `-FailOn`. |
| `1` | No indicator produced an assessment, or sign-in failed during `-CheckPermissionsOnly`. |
| `2` | At least one finding at or above `-FailOn`. |
| `3` | `-CheckPermissionsOnly` found missing Graph permissions. |

## Environments

Indicators are grouped by the platform they target: Active Directory, Entra ID, Okta,
and Hybrid for the four indicators that span AD and Entra ID (Purple Knight files these
under its own Hybrid category). Each group gets its own posture score and grade, as in
the UI.

## How the score is calculated

Reproduced from `ReportGeneration.ResultsStore.RiskAssessment`. Each evaluated indicator
has an exposure of `(100 - indicatorScore) / 100`, where the indicator score comes from
the indicator script itself. Within a severity, the residuals multiply:

```
residual(severity) = product over indicators of ( 1 - basePenalty(severity) * exposure )
penalty(severity)  = ( 1 - residual(severity) ) * severityWeight(severity) * 100
score              = floor( 100 - sum of penalties ), clamped to 0..100
```

| Severity | basePenalty | severityWeight |
| --- | --- | --- |
| Critical | 0.20 | 0.55 |
| High | 0.14 | 0.33 |
| Medium | 0.09 | 0.10 |
| Low | 0.05 | 0.02 |
| Warning | 0 | 0 |
| Informational | 0 | 0 |

Because the residuals compound, each additional finding of the same severity moves the
score less than the previous one, and `Warning` and `Informational` indicators are
reported but never affect the score. Grades use Purple Knight's thresholds:
`A+` 100, `A` 99, `A-` 98, `B+` 96, `B` 93, `B-` 90, `C+` 86, `C` 81, `C-` 75,
`D+` 67, `D` 58, `D-` 44, `F` below 44.

## Scheduling

`examples\Run-Scheduled.ps1` is a ready-made wrapper that reads the Entra ID secret from
a DPAPI-encrypted file, runs the assessment, applies report retention and prints a
one-line summary. Create the secret file once, as the account the task will run under:

```powershell
Read-Host 'Client secret' -AsSecureString |
    Export-Clixml "$env:ProgramData\PurpleKnight\entra-secret.xml"
```

## Notes and limitations

* Nothing under `Scripts\` is modified. Application updates that add or change
  indicators are picked up automatically; the catalog cache invalidates itself when
  module versions change.
* `lib\Semperis.PSSecurityIndicatorResult.dll` is a copy of the result type embedded in
  `PurpleKnight.exe`. If it is ever missing, an equivalent type is compiled at runtime,
  so the CLI keeps working.
* Some indicators need more than LDAP: SYSVOL access, remote registry, or RPC to domain
  controllers. Those report `Error` when blocked, exactly as they would in the UI.
* Indicator parameter overrides work the same way as in the desktop application: place
  `<ScriptName>.json` files in a `Config` folder next to the installation, or set the
  `IOE_<ScriptName>_CONFIG` environment variable.
