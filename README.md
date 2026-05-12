# VanishTotal

VanishTotal is a PowerShell 7 file-triage tool for VirusTotal. It computes the file SHA-256, checks whether VirusTotal already has a report, classifies per-engine results, and produces a weighted enterprise-oriented risk verdict.

## Files

- `VanishTotal.ps1` - CLI and Explorer context-menu entry point.
- `VanishTotal.Core.psm1` - VirusTotal client, retry logic, detection classification, scoring, and JSON report helpers.
- `VanishTotalContextMenu.ps1` - per-user Explorer context-menu manager.
- `VanishTotalContextMenu.cmd` - double-click menu for installing or uninstalling the Explorer context menu.

## Basic Use

```powershell
pwsh -NoProfile -File .\VanishTotal.ps1 -Path 'C:\Path\To\File.exe'
```

By default, VanishTotal performs lookup only. If VirusTotal has no existing report for the file, the file is not uploaded.

To explicitly allow uploads for unknown files:

```powershell
pwsh -NoProfile -File .\VanishTotal.ps1 -Path 'C:\Path\To\File.exe' -UploadUnknownFiles
```

To export an automation-friendly JSON report:

```powershell
pwsh -NoProfile -File .\VanishTotal.ps1 -Path 'C:\Path\To\File.exe' -JsonReportPath '.\reports\sample.json' -NoPause
```

## Explorer Context Menu

The supported setup method is the context-menu manager. It registers the menu for the current Windows user, finds the local PowerShell 7 executable, unblocks the VanishTotal scripts if they were downloaded from the internet, and avoids needing administrator rights:

For the simplest setup, double-click and choose install or uninstall:

```text
VanishTotalContextMenu.cmd
```

Or run the PowerShell manager directly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\VanishTotalContextMenu.ps1
```

The context menu adds a `Scan with VanishTotal` submenu for files. It includes:

- `Normal scan`
- `Scan and upload if unknown`

On Windows 11, the entry may appear under `Show more options`.

To remove the menu:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\VanishTotalContextMenu.ps1 -Uninstall
```

## API Key

Preferred enterprise configuration is to inject the key through the process environment:

```powershell
$env:VT_API_KEY = '<your key>'
```

You can also pass `-ApiKey` or use `-StoreApiKey` to store `VT_API_KEY` for the current Windows user. Avoid hard-coding API keys into scripts, registry files, tickets, or logs.

## Exit Codes

- `0` - clean or low risk
- `1` - error or no usable engine data
- `2` - manual review recommended, or no existing VT report when upload is disabled
- `3` - suspicious
- `4` - high-confidence malicious

## Enterprise Notes

- Unknown-file uploads are opt-in because public VirusTotal submissions can expose proprietary or sensitive files.
- Uploads use PowerShell multipart requests instead of `curl.exe`, avoiding API-key leakage through command-line process listings.
- The console report shows final user-facing classifications for all VirusTotal engines in alphabetical order.
- Labels containing heuristic, PUA/PUP, riskware, hacktool, generic, ML, packed, or suspicious wording can be presented as `Suspicious` even when VirusTotal does not return a literal suspicious category.
- JSON reports retain source and classification detail for SIEM, audit, and analyst workflows.
- File-size upload limits are only applied after hash lookup and only when `-UploadUnknownFiles` is enabled. Large files can still be checked by hash without being uploadable.

## Engine Weights

Engine weights are intentionally conservative. They are not a ranking of products to buy; they only affect how much confidence VanishTotal assigns to a VirusTotal engine result.

The current default weights were calibrated in May 2026 using:

- AV-TEST business Windows endpoint results for February 2026: https://www.av-test.org/en/antivirus/business-windows-client/
- AV-Comparatives Enterprise Malware Protection Test, September 2025: https://www.av-comparatives.org/tests/malware-protection-test-enterprise-september-2025-testresult/
- AV-Comparatives Business Security Test factsheet, August-September 2025: https://www.av-comparatives.org/tests/business-security-test-august-september-2025-factsheet/
- VirusTotal upload-size guidance: https://docs.virustotal.com/reference/files-upload-url
- U.S. Commerce/BIS Kaspersky prohibition notice for U.S. enterprise governance context: https://www.bis.gov/press-release/commerce-department-prohibits-russian-kaspersky-software-u.s.-customers

Kaspersky remains a strong technical detector in independent tests, but its default weight is not maxed because U.S. enterprise users need to account for regulatory and supply-chain risk separately from detection quality.
