#requires -Version 5.1
<#
.SYNOPSIS
    Read-only comparison of Meraki network alert settings against a configurable baseline.

.DESCRIPTION
    NO DASHBOARD CHANGES ARE MADE.

    Core standard:
      - Optionally checks for a central ticketing/alert recipient supplied with -TicketRecipient.
      - Flags "All network admins" for review.
      - Flags core infrastructure/security alert types that should be enabled wherever Meraki exposes them.
      - Flags standard offline timeout differences.
      - Separates conditional alerts (AutoVPN, uplink failover, cellular, warm spare) for review.

    Output:
      %USERPROFILE%\Documents\Meraki-Alerts\Meraki-Alert-Review-YYYYMMDD-HHMMSS\
        Recommended-Changes.csv
        Conditional-Review.csv
        Network-Summary.csv
        Errors.csv
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path $env:USERPROFILE "Documents\Meraki-Alerts"),
    [string]$TicketRecipient = ""
)

$ErrorActionPreference = "Stop"
$BaseUri = "https://api.meraki.com/api/v1"

function Get-PlainTextFromSecureString {
    param([Security.SecureString]$SecureString)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-MerakiApiKey {
    if ($env:MERAKI_DASHBOARD_API_KEY) { return $env:MERAKI_DASHBOARD_API_KEY }
    if ($env:MERAKI_API_KEY) { return $env:MERAKI_API_KEY }

    Write-Host ""
    Write-Host "No Meraki API key environment variable was found." -ForegroundColor Yellow
    $secure = Read-Host "Enter Meraki Dashboard API key" -AsSecureString
    return Get-PlainTextFromSecureString $secure
}

$ApiKey = Get-MerakiApiKey
$Headers = @{
    Authorization = "Bearer $ApiKey"
    Accept        = "application/json"
}

function Invoke-MerakiGet {
    param([Parameter(Mandatory)][string]$Path, [int]$MaxRetries = 6)

    $uri = if ($Path -match '^https?://') { $Path } else { "$BaseUri$Path" }

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -TimeoutSec 90
        }
        catch {
            $status = $null
            $retryAfter = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            try { $retryAfter = $_.Exception.Response.Headers["Retry-After"] } catch {}

            if ($status -eq 429 -and $attempt -lt $MaxRetries) {
                $sleep = 2
                if ($retryAfter) { [int]::TryParse([string]$retryAfter, [ref]$sleep) | Out-Null }
                if ($sleep -lt 1) { $sleep = 1 }
                Start-Sleep -Seconds $sleep
                continue
            }

            throw
        }
    }
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

function Join-Values {
    param($Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [string]) { return $Value }
    return (($Value | ForEach-Object { [string]$_ }) -join "; ")
}

function Add-Change {
    param(
        [string]$Organization,
        [string]$Network,
        [string]$NetworkId,
        [string]$ProductTypes,
        [string]$Category,
        [string]$AlertType,
        [string]$CurrentValue,
        [string]$RecommendedValue,
        [string]$Reason
    )

    $script:Changes.Add([pscustomobject]@{
        Organization     = $Organization
        Network          = $Network
        NetworkId        = $NetworkId
        ProductTypes     = $ProductTypes
        Category         = $Category
        AlertType        = $AlertType
        CurrentValue     = $CurrentValue
        RecommendedValue = $RecommendedValue
        Reason           = $Reason
    })
}

$CoreAlerts = [ordered]@{
    "settingsChanged"                    = "Alert when Dashboard configuration is changed"
    "applianceDown"                      = "Alert when the MX is offline"
    "dhcpNoLeases"                       = "Alert when an MX DHCP scope is exhausted"
    "ipConflict"                         = "Alert when duplicate IPv4 addresses are detected"
    "rogueDhcp"                          = "Alert when a rogue DHCP server is detected"
    "ampMalwareBlocked"                  = "Alert when malware is blocked"
    "ampMalwareDetected"                 = "Alert when previously downloaded content is later identified as malware"
    "switchDown"                         = "Alert when a switch is offline"
    "newDhcpServer"                      = "Alert when a new DHCP server appears on the LAN"
    "powerSupplyDown"                    = "Alert when a switch power supply fails"
    "rpsBackup"                          = "Alert when redundant power supply operation changes"
    "udldError"                          = "Alert on unidirectional link detection errors"
    "switchCriticalTemperature"          = "Alert when a supported switch reaches critical temperature"
    "gatewayDown"                        = "Alert when a gateway AP is offline"
    "repeaterDown"                       = "Alert when a repeater AP is offline"
    "gatewayToRepeater"                  = "Alert when a wired AP falls back to repeater mode"
    "rogueAp"                            = "Alert when a rogue AP is detected"
    "cameraDown"                         = "Alert when a camera is offline"
    "cellularGatewayDown"                = "Alert when a cellular gateway is offline"
    "nodeHardwareFailure"                = "Alert on supported Meraki node hardware failures"
    "sensorDown"                         = "Alert when a sensor is offline"
    "sensorBatteryPercentage"            = "Alert when sensor battery reaches its configured low threshold"
    "sensorBatteryCover"                 = "Alert on sensor battery-cover events"
    "sensorMagneticTampering"            = "Alert on magnetic tampering events"
    "sensorProbeCable"                   = "Alert on sensor probe-cable events"
    "sensorUsbPowerCable"                = "Alert on sensor USB power-cable events"
    "sensorWaterCable"                   = "Alert on sensor water-cable events"
    "sensorPowerSavingScheduleFailureEvent" = "Alert when a sensor power-saving schedule fails"
    "pccExpiredApnsCert"                 = "Alert when the Apple push certificate expires"
}

$ConditionalAlerts = [ordered]@{
    "failoverEvent"          = "Enable where uplink/failover monitoring is desired; review cellular-only designs"
    "cellularUpDown"         = "Enable where the MX actually uses cellular connectivity"
    "vpnConnectivityChange"  = "Enable on sites using AutoVPN when tunnel-up/down emails are desired; can be noisy during flapping"
    "vrrp"                   = "Enable where an MX warm-spare/HA pair is configured"
}

$TimeoutStandard = @{
    "applianceDown"       = 5
    "switchDown"          = 5
    "gatewayDown"         = 5
    "repeaterDown"        = 5
    "cameraDown"          = 5
    "cellularGatewayDown" = 5
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutputDir = Join-Path $OutputRoot "Meraki-Alert-Review-$stamp"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$script:Changes = New-Object System.Collections.Generic.List[object]
$Conditional = New-Object System.Collections.Generic.List[object]
$Summary = New-Object System.Collections.Generic.List[object]
$Errors = New-Object System.Collections.Generic.List[object]

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " MERAKI ALERTS - BASELINE REVIEW (READ ONLY)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "NO DASHBOARD CHANGES WILL BE MADE."
Write-Host ""

try {
    $orgResponse = Invoke-MerakiGet "/organizations?perPage=9000"
    $orgs = @()
    foreach ($item in $orgResponse) { $orgs += $item }
}
catch {
    Write-Host "Unable to list Meraki organizations." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

foreach ($org in $orgs) {
    try {
        $networkResponse = Invoke-MerakiGet "/organizations/$($org.id)/networks?perPage=1000"
        $networks = @()
        foreach ($item in $networkResponse) { $networks += $item }
    }
    catch {
        $Errors.Add([pscustomobject]@{
            Organization = $org.name
            Network      = ""
            NetworkId    = ""
            HttpStatus   = Get-HttpStatusFromException $_
            Endpoint     = "Organization networks"
            Error        = $_.Exception.Message
        })
        continue
    }

    foreach ($network in $networks) {
        $products = Join-Values $network.productTypes

        try {
            $settings = Invoke-MerakiGet "/networks/$($network.id)/alerts/settings"
        }
        catch {
            $Errors.Add([pscustomobject]@{
                Organization = $org.name
                Network      = $network.name
                NetworkId    = $network.id
                HttpStatus   = Get-HttpStatusFromException $_
                Endpoint     = "Network alert settings"
                Error        = $_.Exception.Message
            })
            continue
        }

        $alerts = @()
        foreach ($item in $settings.alerts) { $alerts += $item }

        $currentEmails = @()
        foreach ($email in @($settings.defaultDestinations.emails)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$email)) { $currentEmails += [string]$email }
        }

        $hasTicketRecipient = $null
        if (-not [string]::IsNullOrWhiteSpace($TicketRecipient)) {
            $hasTicketRecipient = $false
            foreach ($email in $currentEmails) {
                if ($email.Trim().ToLowerInvariant() -eq $TicketRecipient.Trim().ToLowerInvariant()) {
                    $hasTicketRecipient = $true
                    break
                }
            }

            if (-not $hasTicketRecipient) {
                $recommended = @($currentEmails + $TicketRecipient | Select-Object -Unique) -join "; "
                Add-Change -Organization $org.name -Network $network.name -NetworkId $network.id `
                    -ProductTypes $products -Category "Recipient" -AlertType "defaultDestinations.emails" `
                    -CurrentValue ($currentEmails -join "; ") -RecommendedValue $recommended `
                    -Reason "Add the supplied central ticketing recipient while preserving existing recipients"
            }
        }

        if ($settings.defaultDestinations.allAdmins -eq $true) {
            Add-Change -Organization $org.name -Network $network.name -NetworkId $network.id `
                -ProductTypes $products -Category "Recipient Review" -AlertType "defaultDestinations.allAdmins" `
                -CurrentValue "True" -RecommendedValue "Review / normally False" `
                -Reason "All network admins currently receive every enabled alert; this can duplicate/noise alerts. Do not remove intentionally configured recipients without review."
        }

        $coreMissing = 0
        $conditionalCount = 0

        foreach ($alert in $alerts) {
            if ($CoreAlerts.Contains($alert.type)) {
                if ($alert.enabled -ne $true) {
                    $coreMissing++
                    Add-Change -Organization $org.name -Network $network.name -NetworkId $network.id `
                        -ProductTypes $products -Category "Core Alert" -AlertType $alert.type `
                        -CurrentValue "Disabled" -RecommendedValue "Enabled" -Reason $CoreAlerts[$alert.type]
                }

                if ($TimeoutStandard.ContainsKey($alert.type)) {
                    $currentTimeout = $null
                    try { $currentTimeout = [int]$alert.filters.timeout } catch {}

                    if ($null -ne $currentTimeout -and $currentTimeout -ne $TimeoutStandard[$alert.type]) {
                        Add-Change -Organization $org.name -Network $network.name -NetworkId $network.id `
                            -ProductTypes $products -Category "Timeout" -AlertType $alert.type `
                            -CurrentValue "$currentTimeout minutes" `
                            -RecommendedValue "$($TimeoutStandard[$alert.type]) minutes" `
                            -Reason "Proposed baseline device-offline notification delay"
                    }
                }
            }

            if ($ConditionalAlerts.Contains($alert.type)) {
                $conditionalCount++
                $Conditional.Add([pscustomobject]@{
                    Organization = $org.name
                    Network      = $network.name
                    NetworkId    = $network.id
                    ProductTypes = $products
                    AlertType    = $alert.type
                    Enabled      = $alert.enabled
                    Guidance     = $ConditionalAlerts[$alert.type]
                })
            }
        }

        $Summary.Add([pscustomobject]@{
            Organization       = $org.name
            Network            = $network.name
            NetworkId          = $network.id
            ProductTypes       = $products
            DefaultEmails      = ($currentEmails -join "; ")
            HasTicketRecipient = $hasTicketRecipient
            AllAdmins          = $settings.defaultDestinations.allAdmins
            CoreAlertsMissing  = $coreMissing
            ConditionalAlerts  = $conditionalCount
        })

        Write-Host ("{0} / {1}: {2} core alert(s) missing" -f $org.name, $network.name, $coreMissing)
    }
}

$ChangesPath = Join-Path $OutputDir "Recommended-Changes.csv"
$ConditionalPath = Join-Path $OutputDir "Conditional-Review.csv"
$SummaryPath = Join-Path $OutputDir "Network-Summary.csv"
$ErrorsPath = Join-Path $OutputDir "Errors.csv"

$Changes | Sort-Object Organization, Network, Category, AlertType |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $ChangesPath
$Conditional | Sort-Object Organization, Network, AlertType |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $ConditionalPath
$Summary | Sort-Object Organization, Network |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $SummaryPath

if ($Errors.Count -gt 0) {
    $Errors | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $ErrorsPath
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " REVIEW COMPLETE - NO CHANGES MADE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Networks reviewed:       $($Summary.Count)"
Write-Host "Recommended changes:     $($Changes.Count)"
Write-Host "Conditional alert rows:  $($Conditional.Count)"
Write-Host "Errors/inaccessible:     $($Errors.Count)"
Write-Host ""
Write-Host "Output folder:"
Write-Host "  $OutputDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "Review the generated CSV files before making any configuration changes."
