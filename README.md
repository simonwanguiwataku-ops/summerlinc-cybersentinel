# Summerlinc CyberSentinel AI — Live KEV Intelligence Desktop v0.3

A local Windows desktop prototype for CyberSentinel's Live KEV Intelligence milestone. It downloads the official CISA Known Exploited Vulnerabilities (KEV) catalog, stores it in a local SQLite database, enriches selected CVEs from NVD, tracks software assets that the operator is authorized to assess, and presents a transparent risk-triage queue.

## What's new in v0.3
- Risk dashboard with counts for KEV records, tracked assets, affected-version leads, items needing review, and ransomware-linked KEVs.
- Priority queue combining KEV status, ransomware flag, NVD CVSS score when available, version-match status, and CISA due date.
- CVSS score, severity, vector, and metric source shown in CVE details after NVD enrichment.
- Risk scores are a documented 0–100 triage heuristic, not a probability of compromise or a substitute for analyst validation.
- Kept the local SQLite database and existing asset records; no cloud migration or CRM changes.

## Requirements
- Windows 10 or Windows 11
- Python 3.10+ (check `python --version`)
- Internet connection for CISA and optional NVD synchronization
- No third-party Python packages required to run the source version

## Run on Windows
1. Extract this ZIP to a folder such as `C:\Summerlinc\CyberSentinel`.
2. Install Python 3.10+ from https://www.python.org/downloads/windows/ if needed. Select **Add Python to PATH** during installation.
3. Double-click `Run_CyberSentinel.bat`.
4. Click **Sync CISA KEV now** to refresh the catalog.
5. Add assets manually or import `sample_assets.csv` after replacing its example entries with assets you are authorized to assess.
6. Select a CVE in **KEV Intelligence** and click **Enrich selected CVE from NVD**. Enrichment is one CVE at a time.
7. Review the **Risk Dashboard**. Prioritize affected-version leads and manual-review items for analyst confirmation.

The local database is stored in `%USERPROFILE%\CyberSentinel\cybersentinel_kev.sqlite3`.

## Asset CSV format
Required columns: `asset_name`, `vendor`, `product`.
Optional columns: `organization`, `version`, `environment`, `owner`, `notes`.

## Risk scoring methodology
The dashboard uses a transparent heuristic, capped at 100:
- Starts at 35 because CISA KEV inclusion indicates exploitation has been observed in the wild.
- Adds 20 for a ransomware-linked KEV flag.
- Adds up to 30 based on CVSS base score when NVD data is available.
- Adds 20 for an NVD affected-version-range lead, or 10 for unknown/manual-review cases.
- Adds up to 10 when the CISA remediation due date has passed or is approaching.
- Reduces the score when NVD CPE does not confirm the preliminary product match or the version is outside the listed range.

Labels: Critical (85–100), High (70–84), Elevated (50–69), Monitor (0–49). The score is a prioritization aid only. It does not estimate exploit likelihood, confirm reachability, prove compromise, or authorize remediation.

## Important limitations and safety
- This remains a local prototype, not a production-ready SaaS product.
- Product/vendor matching is preliminary. NVD CPE data can be incomplete or use naming that differs from an asset inventory. Uncertain cases require manual review.
- A CPE/version match does not prove exploitability, network exposure, or compromise.
- The app does not scan networks, exploit systems, contact customer systems, access customer data, or change configurations.
- Only enter assets you own or have explicit authorization to assess.
- No cloud multi-tenant sync, user authentication, enterprise RBAC, signed auto-updater, or code signing is included.
- CISA KEV is a catalog of known exploited vulnerabilities, not a complete vulnerability database.
- Back up the local database before moving or reinstalling the application.

## Windows executable / installer
- On Windows, run `build_windows_exe.bat` to create `dist\CyberSentinel\CyberSentinel.exe` using PyInstaller.
- To build a conventional installer, install Inno Setup from https://jrsoftware.org/isinfo.php, open `CyberSentinel_Setup.iss`, and compile it after the PyInstaller build.
- This package has not been compiled or code-signed on Windows in this environment. The build scripts are supplied, but the `.exe` and installer still need to be built on a Windows machine.

## Official data sources
- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA JSON feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- NVD CVE API: https://services.nvd.nist.gov/rest/json/cves/2.0
