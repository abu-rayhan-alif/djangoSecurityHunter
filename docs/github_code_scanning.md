# GitHub Code Scanning & PR annotations

`djangoguard` does **not** post inline PR comments by itself. Instead, upload **SARIF** output to **GitHub Code Scanning**; GitHub will show findings on the **Security** tab and attach checks to **pull requests** when Code Scanning is enabled for the repository.

## Enable Code Scanning

1. Repository **Settings → Security → Code security and analysis** → enable **Code scanning**.
2. Ensure the workflow has permission `security-events: write` (see `.github/workflows/ci.yml` in this repo).

## Workflow pattern

```yaml
- name: Scan
  run: |
    mkdir -p reports
    djangoguard scan --project . --format sarif --output reports/djangoguard.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: reports/djangoguard.sarif
```

Use `continue-on-error: true` on the upload step if Code Scanning is not yet enabled (keeps CI green).

## PR experience

After upload, results appear as **Code scanning alerts** and can surface on PRs as **checks** (depending on org/repo settings). This is the supported path for “PR annotations” with SARIF-based tools.
