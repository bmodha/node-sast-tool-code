# Code Review Simulator

Laptop-scale simulation of the code review pipeline. It scans JavaScript on your machine, writes an HTML report, and does not host a model or deploy anything.

A scan prints JSON and writes `sim/out/<repoName>_report.html`. The next scan of the same repository archives the previous report. The first scan starts a local service on `127.0.0.1:47321` so risk ratings can be saved in `sim/out/review.sqlite`.

The architecture blueprint is [docs/architecture/code-review-system.md](docs/architecture/code-review-system.md). Run `node scan.mjs --help` from `sim` for every command, role, and check.

## Saved reports

Sample scan reports are in `sim/out`. Open `dashboard.html` in a browser. It links to the `ID*` reports. The ratings database, scan snapshots, and earlier replay runs stay on this machine.

## Requirements

- Node.js 22 or newer
- npm
- Git, so a new commit is scanned again. Without Git, the commit id is a hash of the folder path and edits in that folder do not trigger a new scan.

Optional. Used only when the command is on `PATH`. A missing command is marked skipped and the rest of the scan still finishes.

- [Gitleaks](https://github.com/gitleaks/gitleaks) for credential patterns
- [Trivy](https://github.com/aquasecurity/trivy) for Terraform misconfiguration (`trivy config` only)

## Install

From the repository root:

```powershell
cd sim
npm install
```

Check the built-in scenarios. This wipes the local database, then prints `replay ok` when the checks pass.

```powershell
npm run replay
```

## Scan

Commands below run from the `sim` directory.

Built-in scenario:

```powershell
node scan.mjs --event fixtures/events/restricted-block.json --as appsec
```

A checkout you cloned. Default data class is `internal`. Use `restricted` when a high-precision finding should block. Point `--source` at the folder that contains the project files, with no trailing backslash.

```powershell
node scan.mjs --source C:\src\<repo> --as developer
node scan.mjs --source C:\src\<repo> --data-class restricted --as appsec
```

Open the HTML file the scan prints, or `http://127.0.0.1:47321/<report-file>` to change risk ratings. Rebuild the summary page without scanning:

```powershell
node scan.mjs --dashboard
```

`--source` allows 2,000 files and 20 MB. A file over 100 KB is skipped. A larger tree stops with a cap error. Scan a subdirectory, or raise `external_max_files` and `external_max_total_bytes` in `sim/policy.json`.

`--as` sets the report view: `developer`, `appsec` (includes redacted secret previews), or `auditor`.
