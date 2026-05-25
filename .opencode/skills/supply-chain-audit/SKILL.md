---
name: supply-chain-audit
description: Use ONLY when the user asks to run a supply chain security audit, dependency audit, or supply chain review on the current project. Covers dependency vulnerability scanning, hash pinning, dependency confusion, CI/CD hardening, Docker hardening, secrets scanning, and automated alerting across all major ecosystems (Python, Node.js, Go, Rust, Ruby, Java, .NET).
---

# Supply Chain Security Audit

Perform a supply chain security audit on the codebase in the current working directory. Find and fix every dependency and configuration weakness that an attacker could exploit. Work through each section below in order. For every finding, fix it or report why it cannot be fixed.

Run all commands yourself — do not ask the user to run them.

---

## 1. DEPENDENCY VULNERABILITY SCAN

Run the appropriate scanner for the project's ecosystem:

**Go:** `govulncheck ./...` (install with `go install golang.org/x/vuln/cmd/govulncheck@latest`)
**Python:** `pip-audit` (install with `pip install pip-audit`)
**Node.js:** `npm audit --production` or `pnpm audit --production`
**Rust:** `cargo audit` (install with `cargo install cargo-audit`)
**Ruby:** `bundle audit check --update`
**Java (Maven):** `mvn dependency-check:check`
**Java (Gradle):** `gradle dependencyCheckAnalyze`
**.NET:** `dotnet list package --vulnerable`

For EVERY vulnerability found:
- Bump the package to the fixed version (prefer the latest patch in the same major line unless the fix requires a major bump)
- Re-run the scanner to confirm zero vulns
- If a fix is unavailable, note the CVE and assess exploitability in this project's context

---

## 2. DEPENDENCY INTEGRITY (HASH PINNING)

Check whether dependency manifests use cryptographically-verified hashes:

**Python:** `requirements.txt` should have `--hash=sha256:...` entries. If bare versions, generate hashes: `pip install pip-tools; pip-compile --generate-hashes requirements.in -o requirements.txt`
**Node.js:** `package-lock.json` / `pnpm-lock.yaml` with `integrity` fields. If missing: `npm install --package-lock-only`
**Go:** `go.sum` should exist with `h1:` hashes. If missing: `go mod tidy`
**Rust:** `Cargo.lock` should be committed (libraries may omit it, binaries must have it)

If the lockfile is in `.gitignore`, un-ignore it and commit it. A lockfile in git prevents dependency confusion and ensures reproducible builds.

---

## 3. DEPENDENCY CONFUSION / TYPOSQUATTING

Check for:
- Private/internal package names in manifests. Verify private registries are configured with scopes/prefixes.
- Package names close to popular packages (check top 500 on the ecosystem's registry). Single character differences are red flags.
- Unmaintained packages: check last publish date and commit activity. No commits in >2 years = higher risk.

---

## 4. TRANSITIVE DEPENDENCY VISIBILITY

Generate the full dependency tree and look for:
- Unmaintained leaf packages (single maintainer, no recent commits)
- Packages with suspiciously low download counts
- Packages pulling native binaries (`.so`, `.dll`, `.dylib`)
- Circular or excessive nesting

**Python:** `pipdeptree` or `pip list --format=json`
**Node.js:** `npm ls --all` or `pnpm why <pkg>`
**Go:** `go mod graph`
**Rust:** `cargo tree`

---

## 5. CI/CD PIPELINE HARDENING

Check `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, etc. for:

- [ ] **Runner pinning:** Replace `ubuntu-latest` / `macos-latest` with specific version like `ubuntu-24.04`. `-latest` is a moving target.
- [ ] **Action pinning:** Every `uses:` directive should reference a specific SHA commit hash, not a tag.
  ```
  # BEFORE (exploitable — tags are mutable)
  uses: actions/checkout@v4
  # AFTER (safe — commit hashes are immutable)
  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
  ```
- [ ] **Token scoping:** The default `GITHUB_TOKEN` has write access. Add `permissions:` block: `permissions: contents: read`
- [ ] **No secrets in logs:** Check that CI scripts never echo/print environment variables or files that might contain secrets.
- [ ] **Pinned language versions:** Replace bare `python-version: "3"` with `"3.12"`. Floating major versions shift underneath you.
- [ ] **No `pull_request_target`** without extreme caution. This event runs in the target repo's context with full secrets.

---

## 6. DOCKER IMAGE HARDENING

If a `Dockerfile` exists, check:

- [ ] **Base image pinned by digest, not tag:**
  ```dockerfile
  # BEFORE (mutable)
  FROM python:3.12-slim
  # AFTER (immutable)
  FROM python:3.12-slim@sha256:abc123...
  ```
- [ ] **Non-root user:** Add `RUN addgroup --system app && adduser --system --group app` and `USER app`
- [ ] **No secrets in layers:** Check for `COPY .env` or `ARG TOKEN` patterns
- [ ] **Minimal base:** Use `-slim` or `-alpine` variants, not full Debian
- [ ] **`--no-cache-dir` on pip install** and `pip cache purge` after

---

## 7. BUILT-IN PROTECTIONS

Check the ecosystem's native supply chain protections:

- [ ] **Python:** `pyproject.toml` should use verified hashes
- [ ] **Node.js:** Prevent lifecycle scripts with `--ignore-scripts` in CI
- [ ] **Go:** Verify `GONOSUMCHECK` and `GONOSUMDB` are not set globally (bypasses checksum database)
- [ ] **Rust:** `Cargo.toml` should not use `[patch]` to override crate sources from unknown locations

---

## 8. AUTOMATED VULN ALERTING

Set up automated monitoring if missing:

- [ ] **GitHub:** Add `.github/dependabot.yml` for the ecosystem:
  ```yaml
  version: 2
  updates:
    - package-ecosystem: "gomod"      # or pip, npm, cargo, etc.
      directory: "/"
      schedule:
        interval: "weekly"
  ```
- [ ] **GitLab:** Enable Dependency Scanning in `.gitlab-ci.yml`
- [ ] **Non-GitHub/GitLab:** Check if Renovate, Snyk, or Socket.dev can be integrated

---

## 9. SECRETS EXPOSURE CHECK

- [ ] Run secrets scanner: `gitleaks detect --no-git` or `trufflehog filesystem .`
- [ ] Verify `.env`, `.pem`, `.key`, `credentials.json`, `service-account.json` are in `.gitignore`
- [ ] Check git history: `git log -p | grep -i 'password\|secret\|token\|key\|api_key'`
- [ ] Remove any `.env.example` that contains real-looking values. Use placeholders only.

---

## 10. PROVENANCE & ATTESTATION (STRETCH)

Check if the ecosystem supports SLSA provenance:

- [ ] **npm:** Packages published with `--provenance` generate sigstore attestations
- [ ] **PyPI:** PEP 740 attestations (emerging). Look for `.intoto.jsonl` files
- [ ] **Go:** Go checksum database (`sum.golang.org`) acts as a transparency log. Verify not bypassed.
- [ ] **Docker:** Build with `docker buildx build --provenance=true` and push with `--sbom=true`

---

## 11. FINAL REPORT

After completing all sections, produce a summary:

```
SUPPLY CHAIN SECURITY AUDIT — COMPLETE

Vulnerabilities found:   X → 0 fixed
Hash pinning:            [MISSING / COMPLETE]
CI runner pinned:        [YES / NO]
Actions pinned by SHA:   [YES / NO]
Secrets scanned:         [CLEAN / ISSUES FOUND — listed below]
Docker non-root:         [YES / NO / N/A]
Dependabot configured:   [YES / NO]
SBOM/provenance:         [NOTED]
Residual risk items:     [list anything that couldn't be fixed]
```
