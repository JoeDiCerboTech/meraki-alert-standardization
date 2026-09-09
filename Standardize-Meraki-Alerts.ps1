#requires -Version 5.1
<#
.SYNOPSIS
    Dry-run-first Cisco Meraki alert standardization across multiple organizations/networks.

.DESCRIPTION
    No Dashboard changes are made unless -Apply is supplied.

    The script:
      - Preserves existing explicit recipients.
      - Optionally adds a central ticketing/alert recipient supplied with -TicketRecipient.
      - Preserves already-enabled site-specific alerts.
      - Enables a conservative baseline only when Meraki exposes that alert type.
      - Normalizes device-offline alert timeouts.
      - Enables primary-uplink, cellular, and HA alerts only when the network design supports them.
      - Leaves AutoVPN alerts disabled by default unless -EnableVpnAlerts is supplied.
      - Leaves configuration-change, IP-conflict, and rogue-AP alerts opt-in.
      - Saves before/planned/after state and performs read-back verification after apply.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path $env:USERPROFILE "Documents\Meraki-Alerts"),
    [string]$TicketRecipient = "",
    [ValidateRange(1,60)][int]$OfflineTimeoutMinutes = 5,
    [switch]$Apply,
    [switch]$EnableVpnAlerts,
    [switch]$EnableConfigChangeAlerts,
    [switch]$EnableIpConflictAlerts,
    [switch]$EnableRogueApAlerts,
    [switch]$DisableAllAdmins,
    [string[]]$ExcludeOrganizations = @(),
    [string[]]$ExcludeNetworks = @()
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
    Write-Host "No Meraki API key environment variable was found." -ForegroundColor Yellow
    $secure = Read-Host "Enter Meraki Dashboard API key" -AsSecureString
    return Get-PlainTextFromSecureString $secure
}

function Get-HttpStatusFromException {
    param($ErrorRecord)
    try { if ($ErrorRecord.Exception.Response) { return [int]$ErrorRecord.Exception.Response.StatusCode } } catch {}
    return $null
}

function Invoke-MerakiRequest {
    param(
        [Parameter(Mandatory)][ValidateSet("GET","PUT")][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Body = $null,
        [int]$MaxRetries = 6
    )

    $uri = if ($Path -match '^https?://') { $Path } else { "$BaseUri$Path" }

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            if ($Method -eq "GET") {
                return Invoke-RestMethod -Method Get -Uri $uri -Headers $script:Headers -TimeoutSec 90
            }

            $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 50 }
            return Invoke-RestMethod -Method Put -Uri $uri -Headers $script:Headers `
                -ContentType "application/json" -Body $json -TimeoutSec 90
        }
        catch {
            $status = Get-HttpStatusFromException $_
            $retryAfter = $null
            try { $retryAfter = $_.Exception.Response.Headers["Retry-After"] } catch {}

            if ($status -eq 429 -and $attempt -lt $MaxRetries) {
                $sleep = 2
                if ($retryAfter) { [int]::TryParse([string]$retryAfter, [ref]$sleep) | Out-Null }
                if ($sleep -lt 1) { $sleep = 1 }
                Write-Host "  Rate limit hit. Waiting $sleep second(s)..." -ForegroundColor Yellow
                Start-Sleep -Seconds $sleep
                continue
            }

            throw
        }
    }
}

function Test-HasProperty {
    param($Object,[string]$Name)
    if ($null -eq $Object) { return $false }
    return ($null -ne $Object.PSObject.Properties[$Name])
}

function Add-PropertyIfMissing {
    param($Object,[string]$Name,$Value)
    if (-not (Test-HasProperty $Object $Name)) {
        $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value
    }
}

function Test-NameExcluded {
    param([string]$Name,[string[]]$Patterns)
    foreach ($pattern in @($Patterns)) {
        if (-not [string]::IsNullOrWhiteSpace($pattern) -and $Name -match $pattern) { return $true }
    }
    return $false
}

function Test-EmailPresent {
    param([string[]]$Emails,[string]$EmailToFind)
    foreach ($email in @($Emails)) {
        if ([string]::IsNullOrWhiteSpace([string]$email)) { continue }
        if ($email.Trim().ToLowerInvariant() -eq $EmailToFind.Trim().ToLowerInvariant()) { return $true }
    }
    return $false
}

function Get-ValidatedAlertJson {
    param($Body,[string]$NetworkName)
    $json = $Body | ConvertTo-Json -Depth 50
    try { $check = $json | ConvertFrom-Json }
    catch { throw "Preflight JSON parse failed for '$NetworkName': $($_.Exception.Message)" }

    if (-not ($check.alerts -is [System.Array])) {
        throw "Preflight JSON validation failed for '$NetworkName': alerts must serialize as an array."
    }

    if ($check.defaultDestinations) {
        foreach ($field in @("emails","httpServerIds")) {
            if ((Test-HasProperty $check.defaultDestinations $field) -and
                $null -ne $check.defaultDestinations.$field -and
                -not ($check.defaultDestinations.$field -is [System.Array])) {
                throw "Preflight JSON validation failed for '$NetworkName': defaultDestinations.$field must be an array."
            }
        }
    }

    return $json
}

function Add-PlanRow {
    param(
        [string]$Organization,[string]$Network,[string]$NetworkId,[string]$ProductTypes,
        [string]$Category,[string]$AlertType,[string]$CurrentValue,[string]$ProposedValue,
        [string]$Reason,[string]$Action = "Change"
    )
    $script:PlanRows.Add([pscustomobject]@{
        Organization=$Organization; Network=$Network; NetworkId=$NetworkId; ProductTypes=$ProductTypes
        Category=$Category; AlertType=$AlertType; CurrentValue=$CurrentValue; ProposedValue=$ProposedValue
        Reason=$Reason; Action=$Action
    })
}

function Add-ConditionalRow {
    param([string]$Organization,[string]$Network,[string]$NetworkId,[string]$AlertType,[string]$DetectedState,[string]$CurrentState,[string]$Recommendation)
    $script:ConditionalRows.Add([pscustomobject]@{
        Organization=$Organization; Network=$Network; NetworkId=$NetworkId; AlertType=$AlertType
        DetectedState=$DetectedState; CurrentState=$CurrentState; Recommendation=$Recommendation
    })
}

$ApiKey = Get-MerakiApiKey
$script:Headers = @{ Authorization = "Bearer $ApiKey"; Accept = "application/json" }

# Conservative low-noise baseline.
$RequiredAlerts = [ordered]@{
    "applianceDown"             = "MX is unreachable from Dashboard"
    "dhcpNoLeases"              = "MX DHCP lease pool is exhausted"
    "rogueDhcp"                 = "Rogue DHCP server is detected"
    "ampMalwareBlocked"         = "Malware download is blocked"
    "ampMalwareDetected"        = "Previously downloaded content is later identified as malware"
    "switchDown"                = "Meraki switch is unreachable from Dashboard"
    "newDhcpServer"             = "New DHCP server is detected by switching"
    "powerSupplyDown"           = "Supported switch power supply goes down"
    "rpsBackup"                 = "Redundant power supply is powering a switch"
    "udldError"                 = "UDLD error is detected"
    "switchCriticalTemperature" = "Supported switch reaches critical temperature"
    "gatewayDown"               = "Gateway AP is unreachable from Dashboard"
    "repeaterDown"              = "Repeater AP is unreachable from Dashboard"
    "gatewayToRepeater"         = "Wired AP falls back to repeater mode"
    "cameraDown"                = "Meraki camera is unreachable from Dashboard"
    "cellularGatewayDown"       = "Meraki cellular gateway is unreachable from Dashboard"
    "nodeHardwareFailure"       = "Supported Meraki node reports hardware failure"
    "sensorDown"                = "Meraki sensor is unreachable from Dashboard"
    "sensorBatteryPercentage"   = "Meraki sensor reports low battery"
    "pccExpiredApnsCert"        = "Apple Push Notification certificate expires"
}

if ($EnableConfigChangeAlerts) { $RequiredAlerts["settingsChanged"] = "Dashboard configuration is changed" }
if ($EnableIpConflictAlerts)    { $RequiredAlerts["ipConflict"] = "Duplicate IPv4 address is detected" }
if ($EnableRogueApAlerts)       { $RequiredAlerts["rogueAp"] = "Rogue access point is detected" }

$OfflineAlertTypes = @("applianceDown","switchDown","gatewayDown","repeaterDown","cameraDown","cellularGatewayDown","sensorDown")

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$modeName = if ($Apply) { "APPLY" } else { "DRY-RUN" }
$OutputDir = Join-Path $OutputRoot "Meraki-Alert-Standard-$modeName-$stamp"
$BeforeDir = Join-Path $OutputDir "Before"
$PlannedDir = Join-Path $OutputDir "Planned"
$AfterDir = Join-Path $OutputDir "After"

New-Item -ItemType Directory -Path $BeforeDir -Force | Out-Null
New-Item -ItemType Directory -Path $PlannedDir -Force | Out-Null
if ($Apply) { New-Item -ItemType Directory -Path $AfterDir -Force | Out-Null }

$script:PlanRows = New-Object System.Collections.Generic.List[object]
$script:ConditionalRows = New-Object System.Collections.Generic.List[object]
$ResultRows = New-Object System.Collections.Generic.List[object]
$ErrorRows = New-Object System.Collections.Generic.List[object]

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " MERAKI ALERT STANDARDIZATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Mode:             $modeName"
Write-Host "Ticket recipient: $(if ([string]::IsNullOrWhiteSpace($TicketRecipient)) { '(not configured)' } else { $TicketRecipient })"
Write-Host "Offline timeout:  $OfflineTimeoutMinutes minute(s)"
Write-Host "Output:           $OutputDir"
Write-Host ""

if ($Apply) {
    Write-Host "APPLY mode can change production Dashboard settings." -ForegroundColor Red
    $confirm = Read-Host "Type APPLY to continue"
    if ($confirm -cne "APPLY") {
        Write-Host "Apply cancelled. No changes were made." -ForegroundColor Yellow
        exit 0
    }
}
else {
    Write-Host "DRY RUN: no Dashboard changes will be made." -ForegroundColor Green
}

try {
    $orgs = @(Invoke-MerakiRequest GET "/organizations?perPage=9000")
}
catch {
    Write-Host "Unable to enumerate organizations: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

foreach ($org in $orgs) {
    if (Test-NameExcluded $org.name $ExcludeOrganizations) {
        Write-Host "SKIP ORG: $($org.name)" -ForegroundColor DarkYellow
        continue
    }

    Write-Host ""
    Write-Host "ORG: $($org.name)" -ForegroundColor Cyan

    try { $networks = @(Invoke-MerakiRequest GET "/organizations/$($org.id)/networks?perPage=1000") }
    catch {
        $ErrorRows.Add([pscustomobject]@{Organization=$org.name;Network="";NetworkId="";Endpoint="Organization networks";HttpStatus=Get-HttpStatusFromException $_;Error=$_.Exception.Message})
        continue
    }

    $uplinkStatusRows = @()
    try { $uplinkStatusRows = @(Invoke-MerakiRequest GET "/organizations/$($org.id)/uplinks/statuses?perPage=1000") }
    catch {
        $ErrorRows.Add([pscustomobject]@{Organization=$org.name;Network="";NetworkId="";Endpoint="Organization uplink statuses";HttpStatus=Get-HttpStatusFromException $_;Error=$_.Exception.Message})
    }

    foreach ($network in $networks) {
        if (Test-NameExcluded $network.name $ExcludeNetworks) {
            Write-Host "  SKIP: $($network.name)" -ForegroundColor DarkYellow
            continue
        }

        $productTypes = (@($network.productTypes) -join "; ")
        Write-Host "  $($network.name) [$productTypes]"

        try { $settings = Invoke-MerakiRequest GET "/networks/$($network.id)/alerts/settings" }
        catch {
            $ErrorRows.Add([pscustomobject]@{Organization=$org.name;Network=$network.name;NetworkId=$network.id;Endpoint="Network alert settings";HttpStatus=Get-HttpStatusFromException $_;Error=$_.Exception.Message})
            continue
        }

        $safeOrg = ($org.name -replace '[\\/:*?"<>|]', '_')
        $safeNet = ($network.name -replace '[\\/:*?"<>|]', '_')
        $baseFileName = "$safeOrg -- $safeNet -- $($network.id)"
        $settings | ConvertTo-Json -Depth 50 | Set-Content (Join-Path $BeforeDir "$baseFileName.json") -Encoding UTF8

        $body = $settings
        if (-not (Test-HasProperty $body "defaultDestinations") -or $null -eq $body.defaultDestinations) {
            if (Test-HasProperty $body "defaultDestinations") { $body.defaultDestinations = [pscustomobject]@{} }
            else { $body | Add-Member NoteProperty "defaultDestinations" ([pscustomobject]@{}) }
        }
        if (-not (Test-HasProperty $body.defaultDestinations "emails") -or $null -eq $body.defaultDestinations.emails) {
            Add-PropertyIfMissing $body.defaultDestinations "emails" ([object[]]@())
            $body.defaultDestinations.emails = [object[]]@()
        }

        $currentEmails = @()
        foreach ($email in @($body.defaultDestinations.emails)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$email)) { $currentEmails += [string]$email }
        }

        $networkChanges = 0

        if (-not [string]::IsNullOrWhiteSpace($TicketRecipient) -and -not (Test-EmailPresent $currentEmails $TicketRecipient)) {
            $newEmails = @($currentEmails + $TicketRecipient | Select-Object -Unique)
            $body.defaultDestinations.emails = [object[]]@($newEmails)
            $networkChanges++
            Add-PlanRow $org.name $network.name $network.id $productTypes "Recipient" "defaultDestinations.emails" ($currentEmails -join "; ") ($newEmails -join "; ") "Add supplied central ticketing recipient while preserving existing recipients"
        }

        $currentAllAdmins = $false
        if (Test-HasProperty $body.defaultDestinations "allAdmins") { $currentAllAdmins = [bool]$body.defaultDestinations.allAdmins }
        if ($DisableAllAdmins -and $currentAllAdmins) {
            $body.defaultDestinations.allAdmins = $false
            $networkChanges++
            Add-PlanRow $org.name $network.name $network.id $productTypes "Recipient" "defaultDestinations.allAdmins" "True" "False" "Explicit -DisableAllAdmins option selected"
        }
        elseif ($currentAllAdmins) {
            Add-PlanRow $org.name $network.name $network.id $productTypes "Review Only" "defaultDestinations.allAdmins" "True" "Preserve" "All network admins currently receive alerts" "No automatic change"
        }

        $alertByType = @{}
        foreach ($a in @($body.alerts)) { if ($a -and (Test-HasProperty $a "type")) { $alertByType[[string]$a.type] = $a } }

        foreach ($type in $RequiredAlerts.Keys) {
            if (-not $alertByType.ContainsKey($type)) { continue }
            $a = $alertByType[$type]
            $enabled = if (Test-HasProperty $a "enabled") { [bool]$a.enabled } else { $false }
            if (-not $enabled) {
                $a.enabled = $true
                $networkChanges++
                Add-PlanRow $org.name $network.name $network.id $productTypes "Required Alert" $type "Disabled" "Enabled" $RequiredAlerts[$type]
            }
        }

        foreach ($type in $OfflineAlertTypes) {
            if (-not $alertByType.ContainsKey($type)) { continue }
            $a = $alertByType[$type]
            if (-not (Test-HasProperty $a "enabled") -or -not [bool]$a.enabled) { continue }

            if (-not (Test-HasProperty $a "filters") -or $null -eq $a.filters) {
                if (Test-HasProperty $a "filters") { $a.filters = [pscustomobject]@{} }
                else { $a | Add-Member NoteProperty "filters" ([pscustomobject]@{}) }
            }

            $currentTimeout = $null
            if (Test-HasProperty $a.filters "timeout") { try { $currentTimeout = [int]$a.filters.timeout } catch {} }
            if ($null -eq $currentTimeout -or $currentTimeout -ne $OfflineTimeoutMinutes) {
                if (Test-HasProperty $a.filters "timeout") { $a.filters.timeout = $OfflineTimeoutMinutes }
                else { $a.filters | Add-Member NoteProperty "timeout" $OfflineTimeoutMinutes }
                $networkChanges++
                $displayCurrent = if ($null -eq $currentTimeout) { "(not set)" } else { "$currentTimeout minute(s)" }
                Add-PlanRow $org.name $network.name $network.id $productTypes "Timeout" $type $displayCurrent "$OfflineTimeoutMinutes minute(s)" "Configured device-offline threshold"
            }
        }

        $hasAppliance = @($network.productTypes) -contains "appliance"
        if ($hasAppliance) {
            $networkUplinkRows = @($uplinkStatusRows | Where-Object { $_.networkId -eq $network.id })
            $interfaces = @()
            foreach ($row in $networkUplinkRows) { foreach ($u in @($row.uplinks)) { if ($u.interface) { $interfaces += [string]$u.interface } } }

            $hasWiredUplink = @($interfaces | Where-Object { $_ -match '^wan[123]$' }).Count -gt 0
            $hasCellularUplink = @($interfaces | Where-Object { $_ -eq 'cellular' }).Count -gt 0

            if ($hasWiredUplink -and $alertByType.ContainsKey("failoverEvent") -and -not [bool]$alertByType["failoverEvent"].enabled) {
                $alertByType["failoverEvent"].enabled = $true
                $networkChanges++
                Add-PlanRow $org.name $network.name $network.id $productTypes "Conditional - Uplink" "failoverEvent" "Disabled" "Enabled" "Wired MX uplink detected"
            }

            if ($hasCellularUplink -and $alertByType.ContainsKey("cellularUpDown") -and -not [bool]$alertByType["cellularUpDown"].enabled) {
                $alertByType["cellularUpDown"].enabled = $true
                $networkChanges++
                Add-PlanRow $org.name $network.name $network.id $productTypes "Conditional - Cellular" "cellularUpDown" "Disabled" "Enabled" "Cellular uplink detected"
            }

            try {
                $warmSpare = Invoke-MerakiRequest GET "/networks/$($network.id)/appliance/warmSpare"
                if ($warmSpare.enabled -eq $true -and $alertByType.ContainsKey("vrrp") -and -not [bool]$alertByType["vrrp"].enabled) {
                    $alertByType["vrrp"].enabled = $true
                    $networkChanges++
                    Add-PlanRow $org.name $network.name $network.id $productTypes "Conditional - HA" "vrrp" "Disabled" "Enabled" "MX warm spare is enabled"
                }
            }
            catch {
                Add-ConditionalRow $org.name $network.name $network.id "vrrp" "Unable to read warm-spare configuration" "" "No automatic HA alert change"
            }

            try {
                $vpn = Invoke-MerakiRequest GET "/networks/$($network.id)/appliance/vpn/siteToSiteVpn"
                $vpnMode = [string]$vpn.mode
                if ($vpnMode -and $vpnMode -ne "none" -and $alertByType.ContainsKey("vpnConnectivityChange")) {
                    $vpnEnabled = [bool]$alertByType["vpnConnectivityChange"].enabled
                    if ($EnableVpnAlerts -and -not $vpnEnabled) {
                        $alertByType["vpnConnectivityChange"].enabled = $true
                        $networkChanges++
                        Add-PlanRow $org.name $network.name $network.id $productTypes "Conditional - AutoVPN" "vpnConnectivityChange" "Disabled" "Enabled" "AutoVPN mode '$vpnMode' detected and -EnableVpnAlerts selected"
                    }
                    else {
                        Add-ConditionalRow $org.name $network.name $network.id "vpnConnectivityChange" "AutoVPN mode: $vpnMode" $(if ($vpnEnabled){"Enabled"}else{"Disabled"}) $(if ($vpnEnabled){"Preserve enabled"}else{"Leave disabled by default; use -EnableVpnAlerts if desired"})
                    }
                }
            }
            catch {
                Add-ConditionalRow $org.name $network.name $network.id "vpnConnectivityChange" "Unable to read AutoVPN configuration" "" "No automatic VPN alert change"
            }
        }

        $plannedJson = Get-ValidatedAlertJson $body $network.name
        $plannedJson | Set-Content (Join-Path $PlannedDir "$baseFileName.json") -Encoding UTF8

        if ($networkChanges -eq 0) {
            $ResultRows.Add([pscustomobject]@{Organization=$org.name;Network=$network.name;NetworkId=$network.id;Mode=$modeName;PlannedChanges=0;Result="Already compliant / no change";Verified=$(if($Apply){"Not needed"}else{"N/A"})})
            Write-Host "    No changes needed." -ForegroundColor DarkGreen
            continue
        }

        if (-not $Apply) {
            $ResultRows.Add([pscustomobject]@{Organization=$org.name;Network=$network.name;NetworkId=$network.id;Mode=$modeName;PlannedChanges=$networkChanges;Result="Dry run only";Verified="N/A"})
            Write-Host "    DRY RUN: $networkChanges change(s) planned." -ForegroundColor Yellow
            continue
        }

        try {
            $null = Invoke-MerakiRequest PUT "/networks/$($network.id)/alerts/settings" $plannedJson
            $after = Invoke-MerakiRequest GET "/networks/$($network.id)/alerts/settings"
            $after | ConvertTo-Json -Depth 50 | Set-Content (Join-Path $AfterDir "$baseFileName.json") -Encoding UTF8

            $verifyOk = $true
            $verifyNotes = New-Object System.Collections.Generic.List[string]

            if (-not [string]::IsNullOrWhiteSpace($TicketRecipient)) {
                if (-not (Test-EmailPresent @($after.defaultDestinations.emails) $TicketRecipient)) {
                    $verifyOk = $false
                    $verifyNotes.Add("Ticket recipient missing after PUT")
                }
            }

            $afterByType = @{}
            foreach ($a in @($after.alerts)) { if ($a.type) { $afterByType[[string]$a.type] = $a } }
            foreach ($type in $RequiredAlerts.Keys) {
                if ($alertByType.ContainsKey($type) -and (-not $afterByType.ContainsKey($type) -or $afterByType[$type].enabled -ne $true)) {
                    $verifyOk = $false
                    $verifyNotes.Add("$type not enabled")
                }
            }

            foreach ($type in @("failoverEvent","cellularUpDown","vrrp","vpnConnectivityChange")) {
                if ($alertByType.ContainsKey($type) -and [bool]$alertByType[$type].enabled) {
                    if (-not $afterByType.ContainsKey($type) -or $afterByType[$type].enabled -ne $true) {
                        $verifyOk = $false
                        $verifyNotes.Add("$type expected enabled but verification failed")
                    }
                }
            }

            $ResultRows.Add([pscustomobject]@{Organization=$org.name;Network=$network.name;NetworkId=$network.id;Mode=$modeName;PlannedChanges=$networkChanges;Result=$(if($verifyOk){"Applied"}else{"Applied - verification warning"});Verified=$(if($verifyOk){"PASS"}else{($verifyNotes -join "; ")})})
            Write-Host $(if($verifyOk){"    APPLIED + VERIFIED: $networkChanges change(s)."}else{"    APPLIED, BUT VERIFICATION FOUND A DIFFERENCE."}) -ForegroundColor $(if($verifyOk){"Green"}else{"Yellow"})
        }
        catch {
            $ErrorRows.Add([pscustomobject]@{Organization=$org.name;Network=$network.name;NetworkId=$network.id;Endpoint="PUT network alert settings";HttpStatus=Get-HttpStatusFromException $_;Error=$_.Exception.Message})
            $ResultRows.Add([pscustomobject]@{Organization=$org.name;Network=$network.name;NetworkId=$network.id;Mode=$modeName;PlannedChanges=$networkChanges;Result="FAILED";Verified=$_.Exception.Message})
            Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

$PlanPath = Join-Path $OutputDir "Change-Plan.csv"
$ConditionalPath = Join-Path $OutputDir "Conditional-Review.csv"
$ResultsPath = Join-Path $OutputDir "Results.csv"
$ErrorsPath = Join-Path $OutputDir "Errors.csv"

$PlanRows | Sort-Object Organization,Network,Category,AlertType | Export-Csv $PlanPath -NoTypeInformation -Encoding UTF8
$ConditionalRows | Sort-Object Organization,Network,AlertType | Export-Csv $ConditionalPath -NoTypeInformation -Encoding UTF8
$ResultRows | Sort-Object Organization,Network | Export-Csv $ResultsPath -NoTypeInformation -Encoding UTF8
if ($ErrorRows.Count -gt 0) { $ErrorRows | Sort-Object Organization,Network,Endpoint | Export-Csv $ErrorsPath -NoTypeInformation -Encoding UTF8 }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Mode:               $modeName"
Write-Host "Networks processed: $($ResultRows.Count)"
Write-Host "Plan/review rows:   $($PlanRows.Count)"
Write-Host "Conditional rows:   $($ConditionalRows.Count)"
Write-Host "Errors/skips:       $($ErrorRows.Count)"
Write-Host "Output folder:      $OutputDir"
Write-Host ""
if (-not $Apply) { Write-Host "NO DASHBOARD CHANGES WERE MADE. Review Change-Plan.csv before using -Apply." -ForegroundColor Green }
