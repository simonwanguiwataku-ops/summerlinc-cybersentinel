# Summerlinc CyberSentinel AI

**Discover. Test. Protect. Verify.**

Windows desktop application for authorized vulnerability-management workflows.

## Project status

This repository has been created for the CyberSentinel Windows release. The source package must be added before the Windows build workflow can run. The desktop MVP currently provides a local CISA KEV catalogue, SQLite persistence, asset inventory, CVE search/enrichment, and risk prioritization. It is not a network scanner and does not exploit systems.

## Add the current source package

1. Download the [CyberSentinel Windows Build Package](https://github.com/simonwanguiwataku-ops/summerlinc-cybersentinel) from the ChatGPT conversation where it was prepared.
2. Extract the ZIP on your PC.
3. Open this repository on GitHub and choose **Add file → Upload files**.
4. Upload the *contents* of the extracted `CyberSentinel_KEV_Desktop` folder into the repository root (including the `.github/workflows` folder).
5. Commit the upload to `main`. GitHub Actions will then run the Windows build.

Do not upload local SQLite databases, API keys, passwords, or other secrets.

## Release verification

A release is not considered complete until the Windows workflow succeeds, both portable and installer artifacts are available, and the application is smoke-tested on Windows. The current MVP is not yet a complete cloud SaaS product.
