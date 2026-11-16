# Build CyberSentinel on Windows with GitHub Actions

1. Create an empty **private** GitHub repository for CyberSentinel (keep it separate from the Summerlinc Sales Assistant CRM).
2. Upload the complete contents of this folder to the repository root, including `.github/workflows/windows-release.yml`.
3. In GitHub, open **Actions** and enable workflows if prompted.
4. Run **Windows build and test** using **Run workflow**, or push to `main`/`master`.
5. Wait for every job step to pass. Download both artifacts from the successful workflow run:
   - `CyberSentinel-Windows-Portable` (extract the folder and run `CyberSentinel.exe`)
   - `CyberSentinel-Windows-Installer` (run the setup executable)

The workflow runs the current unit tests, builds the PyInstaller desktop application on a Windows runner, and compiles the Inno Setup installer. A successful build is not a substitute for manual testing on a Windows PC. Verify first launch, CISA synchronization, CSV import/export, database persistence after restart, and NVD enrichment before distributing it.

No API keys or secrets are required for this workflow. Do not commit API keys, customer data, or production databases.
