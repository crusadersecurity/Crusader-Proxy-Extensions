# Crusader Extensions

Curated marketplace extensions for Crusader Proxy.

The `ext/` directory mirrors the public marketplace surface at `https://crusaderproxy.com/ext/`. Marketplace install commands use those stable Crusader URLs. This repository exists so users and agents can inspect source, diff changes, and submit issues before installing.

Arbitrary plugins are still supported, but they are manual installs: users can preview/install any trusted raw URL or local `.js` file with the Crusader CLI or Extensions screen. Do not treat a local `plugins` folder as the marketplace.

## Add to the marketplace

To get an extension listed in the Crusader marketplace store, open an issue or pull request in this repository. Curated entries are reviewed here, then published under `https://crusaderproxy.com/ext/` with a source link back to the reviewed code.

## Install

Preview before installing:

```powershell
crusader plugin preview https://crusaderproxy.com/ext/jwt-inspector.js
```

Install after review:

```powershell
crusader plugin install https://crusaderproxy.com/ext/jwt-inspector.js
```

Some plugins only read local project data and run on Free. Plugins that raise findings, replay identities, use hosted Beacon, run active probes, or use transport sidecars require the relevant Hunter Pro capability. Crusader shows the requested capabilities before anything runs.

## Catalog

| Plugin | File | Capability profile |
| --- | --- | --- |
| JWT Inspector | `ext/jwt-inspector.js` | Free, local JWT decoder/editor tab |
| Secret Scanner | `ext/secret-scanner.js` | Hunter Pro findings |
| IDOR Insertion Points | `ext/idor-insertion-points.js` | Free scanner insertion point provider |
| Security Header Audit | `ext/security-headers.js` | Hunter Pro findings |
| CORS Auditor | `ext/cors-auditor.js` | Hunter Pro findings |
| GraphQL Introspection Detector | `ext/graphql-introspection.js` | Hunter Pro findings |
| SSRF Target List | `ext/ssrf-targets.js` | Free Intruder payload generator |
| Base64 Payload Wrapper | `ext/base64-payload-wrapper.js` | Free Intruder payload processor |
| BlindSpot Beacon Hunter | `ext/blindspot-beacon-hunter.js` | Hunter Pro Beacon and findings |
| Fingerprint Flip | `ext/fingerprint-flip.js` | Transport A/B, Hunter Pro findings |
| Shadow Matrix | `ext/shadow-matrix.js` | Hunter Pro identity replay and findings |
| SSRF Cannon | `ext/ssrf-cannon.js` | Hunter Pro Beacon and findings |

## Safety

Only run active plugins against systems you are authorized to test. Use `crusader plugin preview <url>` to inspect requested capabilities before install.

## License

MIT. See `LICENSE`.
