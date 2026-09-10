# Verifying mcp-visor releases

Every `v*` tag produces, via the `Release` workflow (no long-lived keys;
keyless Sigstore OIDC):

| Asset | What it proves |
|---|---|
| `checksums.txt` (+ `.sig` bundle) | Integrity of every archive; signature bound to this repo's release workflow identity |
| `*.sbom.json` | Machine-readable SBOM per archive (covered by `checksums.txt`) |
| SLSA attestation | Build provenance, verifiable with `gh` |

Verify a download (replace `vX.Y.Z` and `<version>` with the release tag and
version, e.g. tag `v1.4.2` → version `1.4.2`):

```bash
# verify only the archive you downloaded (checksums.txt lists every archive)
ASSET=mcp-visor_<version>_linux_amd64.tar.gz  # or the darwin_amd64/arm64 asset
grep "$ASSET" checksums.txt | sha256sum -c   # Linux
grep "$ASSET" checksums.txt | shasum -a 256 -c  # macOS
gh attestation verify checksums.txt --repo themayursinha/mcp-visor
cosign verify-blob --bundle checksums.txt.sig \
  --certificate-identity 'https://github.com/themayursinha/mcp-visor/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Requires `gh` (with attestation support) and cosign v3 for the bundle format.
`gh attestation verify` alone is sufficient for provenance; the cosign bundle
adds an independent signature check on the same file.

If the SLSA attestation is absent for a release (failed attest job), the
cosign signature above is unaffected — it ships inside goreleaser's publish.
Provenance is backfilled by re-running only the failed `attest` job, which
re-fetches `checksums.txt` from the published release itself: there is no CI
artifact to expire and no publisher to rerun, so recovery cannot collide with
shipped assets.
