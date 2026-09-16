#requires -Version 5.1
<#
.SYNOPSIS
    Read-only audit of Cisco Meraki email alert settings across every organization/network
    visible to the supplied Dashboard API key.

.DESCRIPTION
    NO CONFIGURATION CHANGES ARE MADE.

    Exports:
      - Alerts-By-Site.csv
      - Site-Summary.csv
      - Organization-Alert-Profiles.csv
      - Errors.csv (only if errors occur)
      - Raw JSON copies of each network's alert settings

    API key lookup order:
      1. MERAKI_DASHBOARD_API_KEY environment variable
      2. MERAKI_API_KEY environment variable
      3. Secure prompt
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path $env:USERPROFILE "Documents\Meraki-Alerts")
)

$ErrorActionPreference = "Stop"
$BaseUri = "https://api.meraki.com/api/v1"

function Get-PlainTextFromSecureString {
    param([Security.SecureString]$SecureString)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-MerakiApiKey {
    if ($env:MERAKI_DASHBOARD_API_KEY) {
        return $env:MERAKI_DASHBOARD_API_KEY
    }
    if ($env:MERAKI_API_KEY) {
        return $env:MERAKI_API_KEY
    }

    Write-Host ""
    Write-Host "No Meraki API key environment variable was found." -ForegroundColor Yellow
    $secure = Read-Host "Enter Meraki Dashboard API key" -AsSecureString
    return Get-PlainTextFromSecureString $secure
}

$ApiKey = Get-MerakiApiKey

$Headers = @{
    "Authorization" = "Bearer $ApiKey"
    "Accept"        = "application/json"
}

function Invoke-MerakiGet {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$MaxRetries = 6
    )

    $uri = if ($Path -match '^https?://') { $Path } else { "$BaseUri$Path" }

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -TimeoutSec 90
        }
        catch {
            $status = $null
            $retryAfter = $null

            if ($_.Exception.Response) {
                try { $status = [int]$_.Exception.Response.StatusCode } catch {}
                try { $retryAfter = $_.Exception.Response.Headers["Retry-After"] } catch {}
            }

            if ($status -eq 429 -and $attempt -lt $MaxRetries) {
                $sleep = 2
                if ($retryAfter) {
                    [int]::TryParse([string]$retryAfter, [ref]$sleep) | Out-Null
                }
                if ($sleep -lt 1) { $sleep = 1 }
                Write-Host "  API rate limit hit. Waiting $sleep second(s)..." -ForegroundColor Yellow
                Start-Sleep -Seconds $sleep
                continue
            }

            throw
        }
    }
}

function Convert-ToJoinedString {
    param($Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [string]) { return $Value }
    try { return (($Value | ForEach-Object { [string]$_ }) -join "; ") }
    catch { return [string]$Value }
}

function Convert-ToCompactJson {
    param($Value)
    if ($null -eq $Value) { return "" }
    try { return ($Value | ConvertTo-Json -Depth 20 -Compress) }
    catch { return [string]$Value }
}

function Get-HttpStatusFromException {
    param($ErrorRecord)
    try {
        if ($ErrorRecord.Exception.Response) {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
    } catch {}
    return $null
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutputDir = Join-Path $OutputRoot "Meraki-Alert-Audit-$stamp"
$RawDir = Join-Path $OutputDir "Raw"

New-Item -ItemType Directory -Path $RawDir -Force | Out-Null

$alertRows = New-Object System.Collections.Generic.List[object]
$siteRows  = New-Object System.Collections.Generic.List[object]
$orgRows   = New-Object System.Collections.Generic.List[object]
$errorRows = New-Object System.Collections.Generic.List[object]

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " MERAKI ALERT AUDIT V3 - READ ONLY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Output: $OutputDir"
Write-Host ""

try {
    $orgResponse = Invoke-MerakiGet "/organizations?perPage=9000"
    $orgs = @()
    foreach ($item in $orgResponse) { $orgs += $item }
}
catch {
    Write-Host "ERROR: Unable to list Meraki organizations." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

Write-Host "Organizations found: $($orgs.Count)" -ForegroundColor Green

foreach ($org in $orgs) {
    if ($org.id -is [array] -or [string]::IsNullOrWhiteSpace([string]$org.id)) {
        throw "Invalid organization object returned by API. Organization ID was not a scalar value."
    }

    Write-Host ""
    Write-Host "ORG: $($org.name)" -ForegroundColor Cyan

    try {
        $profileResponse = Invoke-MerakiGet "/organizations/$($org.id)/alerts/profiles"
        $profiles = @()
        foreach ($item in $profileResponse) { $profiles += $item }
        foreach ($profile in $profiles) {
            $orgRows.Add([pscustomobject]@{
                Organization        = $org.name
                OrganizationId      = $org.id
                ProfileId           = $profile.id
                AlertType           = $profile.type
                Enabled             = $profile.enabled
                Emails              = Convert-ToJoinedString $profile.recipients.emails
                NetworkTags         = Convert-ToJoinedString $profile.networkTags
                Description         = $profile.description
                AlertConditionJson  = Convert-ToCompactJson $profile.alertCondition
                WebhookCount        = @($profile.recipients.httpServerIds).Count
            })
        }
    }
    catch {
        $status = Get-HttpStatusFromException $_
        $errorRows.Add([pscustomobject]@{
            Organization   = $org.name
            Network        = ""
            NetworkId      = ""
            Endpoint       = "Organization alert profiles"
            HttpStatus     = $status
            Error          = $_.Exception.Message
        })
        Write-Host "  Org alert profiles: skipped/error ($status)" -ForegroundColor DarkYellow
    }

    try {
        $networkResponse = Invoke-MerakiGet "/organizations/$($org.id)/networks?perPage=1000"
        $networks = @()
        foreach ($item in $networkResponse) { $networks += $item }
    }
    catch {
        $status = Get-HttpStatusFromException $_
        $errorRows.Add([pscustomobject]@{
            Organization   = $org.name
            Network        = ""
            NetworkId      = ""
            Endpoint       = "Organization networks"
            HttpStatus     = $status
            Error          = $_.Exception.Message
        })
        Write-Host "  Could not list networks for this organization." -ForegroundColor Red
        continue
    }

    Write-Host "  Networks found: $($networks.Count)"

    foreach ($network in $networks) {
        if ($network.id -is [array] -or [string]::IsNullOrWhiteSpace([string]$network.id)) {
            Write-Host "  - Skipping invalid network object (missing/scalar Network ID)." -ForegroundColor Red
            continue
        }

        $products = Convert-ToJoinedString $network.productTypes
        Write-Host ("  - {0} [{1}]" -f $network.name, $products)

        try {
            $settings = Invoke-MerakiGet "/networks/$($network.id)/alerts/settings"

            $safeOrg = ($org.name -replace '[\\/:*?"<>|]', '_')
            $safeNet = ($network.name -replace '[\\/:*?"<>|]', '_')
            $rawPath = Join-Path $RawDir "$safeOrg -- $safeNet -- $($network.id).json"
            $settings | ConvertTo-Json -Depth 40 | Set-Content -Path $rawPath -Encoding UTF8

            $alerts = @()
            foreach ($item in $settings.alerts) { $alerts += $item }
            $enabledCount = @($alerts | Where-Object { $_.enabled -eq $true }).Count
            $disabledCount = @($alerts | Where-Object { $_.enabled -ne $true }).Count

            $siteRows.Add([pscustomobject]@{
                Organization          = $org.name
                OrganizationId        = $org.id
                Network               = $network.name
                NetworkId             = $network.id
                ProductTypes          = $products
                TimeZone              = $network.timeZone
                Tags                  = Convert-ToJoinedString $network.tags
                DefaultEmails         = Convert-ToJoinedString $settings.defaultDestinations.emails
                DefaultAllAdmins      = $settings.defaultDestinations.allAdmins
                DefaultSNMP           = $settings.defaultDestinations.snmp
                DefaultWebhookCount   = @($settings.defaultDestinations.httpServerIds).Count
                TotalAlertTypes       = $alerts.Count
                EnabledAlertTypes     = $enabledCount
                DisabledAlertTypes    = $disabledCount
                RawJsonFile           = $rawPath
            })

            foreach ($alert in $alerts) {
                $specificEmails = ""
                $specificAllAdmins = $null
                $specificSnmp = $null
                $sms = ""
                $webhookCount = 0

                if ($alert.alertDestinations) {
                    $specificEmails = Convert-ToJoinedString $alert.alertDestinations.emails
                    $specificAllAdmins = $alert.alertDestinations.allAdmins
                    $specificSnmp = $alert.alertDestinations.snmp
                    $sms = Convert-ToJoinedString $alert.alertDestinations.smsNumbers
                    $webhookCount = @($alert.alertDestinations.httpServerIds).Count
                }

                $alertRows.Add([pscustomobject]@{
                    Organization          = $org.name
                    OrganizationId        = $org.id
                    Network               = $network.name
                    NetworkId             = $network.id
                    ProductTypes          = $products
                    AlertType             = $alert.type
                    Enabled               = $alert.enabled
                    DefaultEmails         = Convert-ToJoinedString $settings.defaultDestinations.emails
                    DefaultAllAdmins      = $settings.defaultDestinations.allAdmins
                    SpecificEmails        = $specificEmails
                    SpecificAllAdmins     = $specificAllAdmins
                    SMSNumbers            = $sms
                    SNMP                  = $specificSnmp
                    WebhookCount          = $webhookCount
                    FiltersJson           = Convert-ToCompactJson $alert.filters
                })
            }
        }
        catch {
            $status = Get-HttpStatusFromException $_
            $errorRows.Add([pscustomobject]@{
                Organization   = $org.name
                Network        = $network.name
                NetworkId      = $network.id
                Endpoint       = "Network alert settings"
                HttpStatus     = $status
                Error          = $_.Exception.Message
            })

            Write-Host "      Alert settings skipped/error ($status)" -ForegroundColor DarkYellow
        }
    }
}

$alertsCsv = Join-Path $OutputDir "Alerts-By-Site.csv"
$sitesCsv  = Join-Path $OutputDir "Site-Summary.csv"
$orgCsv    = Join-Path $OutputDir "Organization-Alert-Profiles.csv"
$errorsCsv = Join-Path $OutputDir "Errors.csv"

$alertRows | Sort-Object Organization, Network, AlertType |
    Export-Csv -Path $alertsCsv -NoTypeInformation -Encoding UTF8

$siteRows | Sort-Object Organization, Network |
    Export-Csv -Path $sitesCsv -NoTypeInformation -Encoding UTF8

$orgRows | Sort-Object Organization, AlertType |
    Export-Csv -Path $orgCsv -NoTypeInformation -Encoding UTF8

if ($errorRows.Count -gt 0) {
    $errorRows | Sort-Object Organization, Network, Endpoint |
        Export-Csv -Path $errorsCsv -NoTypeInformation -Encoding UTF8
}

$variance = $alertRows |
    Group-Object Organization, AlertType |
    ForEach-Object {
        $rows = @($_.Group)
        $states = @($rows.Enabled | Select-Object -Unique)
        if ($states.Count -gt 1) {
            [pscustomobject]@{
                Organization = $rows[0].Organization
                AlertType    = $rows[0].AlertType
                EnabledSites = @($rows | Where-Object Enabled -eq $true).Count
                DisabledSites= @($rows | Where-Object Enabled -ne $true).Count
            }
        }
    } |
    Sort-Object Organization, AlertType

$varianceCsv = Join-Path $OutputDir "Alert-Variances.csv"
$variance | Export-Csv -Path $varianceCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " AUDIT COMPLETE - NO CHANGES WERE MADE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Sites audited:         $($siteRows.Count)"
Write-Host "Alert rows exported:   $($alertRows.Count)"
Write-Host "Org alert profiles:    $($orgRows.Count)"
Write-Host "Errors/skips:          $($errorRows.Count)"
Write-Host ""
Write-Host "Main files:"
Write-Host "  $sitesCsv"
Write-Host "  $alertsCsv"
Write-Host "  $varianceCsv"
Write-Host "  $orgCsv"
if ($errorRows.Count -gt 0) {
    Write-Host "  $errorsCsv"
}
Write-Host ""
Write-Host "Output folder:"
Write-Host "  $OutputDir" -ForegroundColor Cyan
Write-Host ""
