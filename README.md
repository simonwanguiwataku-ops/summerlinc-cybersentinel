# Summerlinc CyberSentinel AI

**Discover. Test. Protect. Verify.**

Windows desktop application for authorized vulnerability-management workflows.

## Project status

This repository is the GitHub home for the CyberSentinel Windows release. The initial repository setup is complete; the application source package has not yet been committed. The desktop MVP provides a local CISA KEV catalogue, SQLite persistence, asset inventory, CVE search/enrichment, and risk prioritization. It is not a network scanner and does not exploit systems.

## Add the application source

The project ZIP is attached in the ChatGPT conversation as **Summerlinc_CyberSentinel_Windows_Build_Package_v2.zip**.

1. Download and extract that ZIP on your Windows PC.
2. Open the extracted `CyberSentinel_KEV_Desktop` folder.
3. Upload the *contents* of that folder into this repository's root using **Add file → Upload files**. Include the hidden `.github` folder and its workflow file.
4. Commit the upload to `main`.

After the source is committed, GitHub Actions will run the Windows test and packaging workflow. Do not upload local SQLite databases, API keys, passwords, or other secrets.

## Release verification

A release is not complete until the Windows workflow succeeds, both portable and installer artifacts are available, and the application is smoke-tested on Windows. The current MVP is not yet a complete cloud SaaS product.
