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

## Getting Purple Knight

The CLI is a runner, not a replacement: it needs a Purple Knight Community installation
next to it, because the indicator scripts, the `Semperis-Lib` helper module and the
result type all come from that installation.

Purple Knight Community is free. Semperis distributes it from
[purple-knight.com](https://www.purple-knight.com/) — request it there with a business
email address and a download link arrives by mail. It ships as a ZIP archive
(`Purple-Knight-<version>.zip`), not an installer, so "installing" it means unblocking
and extracting the archive wherever you want it to live:

```powershell
Unblock-File .\Purple-Knight-*.zip
Expand-Archive .\Purple-Knight-*.zip -DestinationPath 'C:\Tools\PurpleKnight'
```

Extract to a path the running account can write to — Purple Knight writes its `Output`
and `Logs` folders underneath itself, and so does this CLI. Avoid `C:\Program Files`
for that reason. A folder that already holds Purple Knight looks like this:

```
C:\Tools\PurpleKnight\
  PurpleKnight.exe
  Settings.xml
  Scripts\
    Scripts.config.xml
    Semperis.SI.<name>\<version>\<name>.ps1
    Semperis-Lib\...
```

`Scripts\Scripts.config.xml` is the marker the CLI looks for when it locates an
installation, so if that file is not there the archive was not fully extracted.

You never have to launch `PurpleKnight.exe` before using the CLI. Running the desktop
application once is only worth doing if you want it to extract
`Semperis.PSSecurityIndicatorResult.dll` to `%TEMP%` — and even that is optional, since
this repository ships a copy under `lib\` and the CLI compiles an equivalent type when
neither is available.

To upgrade, extract the new Purple Knight release over the same folder and keep the
`CLI` folder in place. New and changed indicators are picked up on the next run; the
catalog cache invalidates itself when indicator module versions change.

## Deployment

The CLI is a folder of PowerShell files with nothing to compile and nothing to register.
Deploying it means putting this repository into a folder named `CLI` **inside** the
Purple Knight installation directory:

```
C:\Tools\PurpleKnight\        <- InstallPath
  PurpleKnight.exe
  Scripts\                    <- indicators and Semperis-Lib, untouched
  Output\                     <- default report location
  CLI\                        <- this repository
    Invoke-PurpleKnight.ps1     entry point
    PurpleKnightCli.psm1        discovery, execution, scoring and reporting
    lib\                        Semperis.PSSecurityIndicatorResult.dll (result type)
    cache\                      cached indicator catalog, rebuilt automatically
    examples\                   sample config file and scheduled-task wrapper
```

That layout is the one the CLI is built around: with no `-InstallPath` given, it takes
the parent of its own folder as the installation, so everything resolves without
configuration. It is also where the CLI caches the indicator catalog (`CLI\cache`) and
the result-type assembly (`CLI\lib`).

Clone it directly into place:

```powershell
git clone https://github.com/jazofra/PurpleKnightCLI.git 'C:\Tools\PurpleKnight\CLI'
```

Or, if you downloaded the repository as a ZIP, extract it and unblock the files — files
that came from a browser download carry the mark-of-the-web and PowerShell refuses to
load them:

```powershell
Expand-Archive .\PurpleKnightCLI-main.zip -DestinationPath $env:TEMP\pkcli
Copy-Item "$env:TEMP\pkcli\PurpleKnightCLI-main\*" 'C:\Tools\PurpleKnight\CLI' -Recurse
Get-ChildItem 'C:\Tools\PurpleKnight\CLI' -Recurse | Unblock-File
```

Verify the deployment — this loads the catalog from the installation and prints it,
without touching any directory or tenant:

```powershell
pwsh -File 'C:\Tools\PurpleKnight\CLI\Invoke-PurpleKnight.ps1' -ListIndicators
```

If it reports that it could not locate a Purple Knight installation, the `CLI` folder is
not where it expects; see the next section.

### Keeping the CLI somewhere else

The `CLI`-inside-the-installation layout is only the default. The CLI resolves the
installation directory in this order and takes the first candidate that contains
`Scripts\Scripts.config.xml`:

1. `-InstallPath`
2. the parent of the folder holding `Invoke-PurpleKnight.ps1`
3. `$env:PURPLEKNIGHT_HOME`
4. the current directory

So a checkout kept outside the installation works just as well, as long as one of the
other candidates points at it:

```powershell
# per invocation
pwsh -File C:\Repos\PurpleKnightCLI\Invoke-PurpleKnight.ps1 -InstallPath 'C:\Tools\PurpleKnight' -Target AD

# or once, for the machine
[Environment]::SetEnvironmentVariable('PURPLEKNIGHT_HOME', 'C:\Tools\PurpleKnight', 'Machine')
```

Keeping the CLI outside the installation has one practical advantage: a Purple Knight
upgrade that replaces the whole folder cannot take your checkout with it. The cost is
that `cache\` and `lib\` are then written under the installation's own `CLI\` folder
rather than next to your scripts.

### PowerShell 7

The desktop application hosts PowerShell 7.4, so the indicators expect `pwsh`, not
Windows PowerShell 5.1. If `pwsh` is not on the machine:

```powershell
winget install --id Microsoft.PowerShell --source winget
```

`pwsh -Version` should report 7.0 or later. No modules need to be installed from the
gallery — the indicators use `Semperis-Lib` from the installation, and everything else
they need is in the box.

### Deploying to a run host

Purple Knight assesses remote environments, so the CLI usually lives on one host —
a jump box, an admin workstation or a scheduled-task server — rather than on the domain
controllers. That host needs:

* line of sight to what it assesses: LDAP/LDAPS (389/636), Global Catalog (3268/3269),
  SMB to `SYSVOL` (445), RPC and remote registry for the handful of indicators that need
  them, and outbound HTTPS to `graph.microsoft.com` for Entra ID or to your Okta domain;
* an account with the permissions Purple Knight normally needs — a plain domain user
  covers most AD indicators;
* for Entra ID or Okta, the app registration or API token, ideally supplied through the
  `PK_*` environment variables or a config file rather than on the command line.

To push the same deployment to several hosts, copy the installation folder with the
`CLI` folder already inside it; there is no per-machine state in either. Delete
`CLI\cache\indicator-catalog.json` before copying if the target machines run a different
Purple Knight version, or pass `-RefreshCatalog` on the first run there.

For an air-gapped or restricted host, carry in the Purple Knight ZIP, this repository
and the PowerShell 7 MSI. Nothing else is fetched at run time: the CLI has no package
dependencies and never calls out to Semperis.

Once deployed, `examples\Run-Scheduled.ps1` turns the CLI into a recurring assessment —
see [Scheduling](#scheduling) below.

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

## Credits

Purple Knight is built and maintained by **[Semperis](https://www.semperis.com/)**, and
all of the security research in it is theirs. Every indicator of exposure this CLI runs
is a Semperis script, executed unmodified from the Purple Knight installation; the
posture score, severity weights and grade thresholds are Semperis' algorithm, reproduced
so the numbers match the desktop application; and connection, token and directory
handling are done through Semperis' own `Semperis-Lib` module.

* [Purple Knight](https://www.purple-knight.com/) — the free community assessment tool
* [Semperis](https://www.semperis.com/) — Purple Knight, Directory Services Protector and
  the identity security research behind them

This project is an independent, unofficial command line front end. It is not affiliated
with, endorsed by, or supported by Semperis, and it ships no Semperis code: the indicator
scripts and helper modules come from the Purple Knight installation you download from
Semperis yourself, under Semperis' own licence terms. For anything about the indicators,
the findings or the product, go to Semperis — not here.
