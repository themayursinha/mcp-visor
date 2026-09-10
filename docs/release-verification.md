# Verifying mcp-visor releases

Every `v*` tag produces, via the `Release` workflow (no long-lived keys;
keyless Sigstore OIDC):

| Asset | What it proves |
|---|---|
| `checksums.txt` (+ `.sig` bundle) | Integrity of every archive; signature bound to this repo's release workflow identity |
| `*.sbom.json` | Machine-readable SBOM per archive (covered by `checksums.txt`) |
| SLSA attestation | Build provenance, verifiable with `gh` |

Verify a download (replace `vX.Y.Z`):

```bash
sha256sum -c --ignore-missing checksums.txt
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
Provenance is backfilled by re-running only the failed `attest` job; the
publisher never reruns, so no republish or collision is possible.
