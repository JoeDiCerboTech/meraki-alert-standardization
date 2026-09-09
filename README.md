# Meraki Alert Standardization

Audit and standardize Cisco Meraki alert settings across multiple organizations and networks with PowerShell and the Meraki Dashboard API.

This toolkit was built from a real multi-organization audit. In that test, 15 organizations and 37 networks produced 872 alert-setting rows and 334 initial findings. The final remediation workflow planned 252 automatic changes, then a separate configuration-change alert pass added 11 more changes for 263 total automated configuration changes.

## Scripts

### `Audit-Meraki-Alerts.ps1`
Read-only inventory of Meraki network alert settings. It exports per-network and per-alert CSV reports, organization alert profiles, variance data, error details, and raw JSON snapshots.

### `Compare-Meraki-Alerts.ps1`
Read-only comparison against a practical baseline. It flags missing core alerts, inconsistent offline thresholds, recipient issues, and conditional alerts that should be reviewed based on network design.

### `Standardize-Meraki-Alerts.ps1`
Dry-run-first remediation script. It preserves existing explicit recipients and already-enabled site-specific alerts, builds an exact change plan, validates the JSON before submission, and performs a read-back verification after changes are applied.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Cisco Meraki Dashboard API access
- An API key with permission to the organizations/networks you intend to audit

No Meraki PowerShell module or SDK is required.

## API key

The scripts look for the API key in this order:

1. `MERAKI_DASHBOARD_API_KEY`
2. `MERAKI_API_KEY`
3. Secure interactive prompt

Do not hard-code an API key into these scripts or commit one to GitHub.

## Quick start

Read-only audit:

```powershell
.\Audit-Meraki-Alerts.ps1
```

Read-only baseline comparison:

```powershell
.\Compare-Meraki-Alerts.ps1
```

If you want to check for a central ticketing/alert recipient without exposing a real address in the script:

```powershell
.\Compare-Meraki-Alerts.ps1 -TicketRecipient "alerts@example.com"
```

Safe remediation preview — **dry run is the default**:

```powershell
.\Standardize-Meraki-Alerts.ps1 -TicketRecipient "alerts@example.com"
```

After reviewing `Change-Plan.csv`, explicitly apply the plan:

```powershell
.\Standardize-Meraki-Alerts.ps1 -Apply -TicketRecipient "alerts@example.com"
```

Optional alert families can be enabled deliberately:

```powershell
.\Standardize-Meraki-Alerts.ps1 -Apply `
    -TicketRecipient "alerts@example.com" `
    -EnableConfigChangeAlerts `
    -EnableVpnAlerts
```

## Conservative behavior

The standardizer intentionally does **not** enable every possible Meraki alert by default. Configuration-change, IP-conflict, rogue-AP, and AutoVPN connectivity alerts are opt-in because alerting needs and noise tolerance vary between environments.

It also does not disable `All network admins` unless `-DisableAllAdmins` is explicitly supplied.

## Output

By default, output is written below:

```text
%USERPROFILE%\Documents\Meraki-Alerts
```

The standardizer creates timestamped folders containing:

- `Before` JSON snapshots
- `Planned` JSON payloads
- `After` JSON snapshots when `-Apply` is used
- `Change-Plan.csv`
- `Conditional-Review.csv`
- `Results.csv`
- `Errors.csv` when applicable

## Safety

Always run the dry run first and inspect the change plan before using `-Apply`.

Before sharing exported data publicly, remove customer names, organization IDs, network IDs, dashboard URLs, internal email addresses, and any other identifying information.

Cisco Meraki alert types and API behavior can change over time. Test against a non-production network first when possible and review the current Meraki API documentation before making large-scale changes.

## License

MIT
