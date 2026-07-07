# Crusader Extensions

Community extensions for Crusader Proxy.

Each plugin is a single JavaScript file that Crusader can preview and install directly from a URL. The published catalog is intentionally simple: read the source, preview the capability manifest, then install only what you approve.

## Install

Preview before installing:

```powershell
crusader plugin preview https://raw.githubusercontent.com/crusadersecurity/extensions/main/plugins/jwt-inspector.js
```

Install after review:

```powershell
crusader plugin install https://raw.githubusercontent.com/crusadersecurity/extensions/main/plugins/jwt-inspector.js
```

Some plugins only read local project data and run on Free. Plugins that raise findings, replay identities, use hosted Beacon, run active probes, or use transport sidecars require the relevant Hunter Pro capability. Crusader shows the requested capabilities before anything runs.

## Catalog

| Plugin | File | Capability profile |
| --- | --- | --- |
| JWT Inspector | `plugins/jwt-inspector.js` | Free, local JWT decoder/editor tab |
| Secret Scanner | `plugins/secret-scanner.js` | Hunter Pro findings |
| IDOR Insertion Points | `plugins/idor-insertion-points.js` | Free scanner insertion point provider |
| Security Header Audit | `plugins/security-headers.js` | Hunter Pro findings |
| CORS Auditor | `plugins/cors-auditor.js` | Hunter Pro findings |
| GraphQL Introspection Detector | `plugins/graphql-introspection.js` | Hunter Pro findings |
| SSRF Target List | `plugins/ssrf-targets.js` | Free Intruder payload generator |
| Base64 Payload Wrapper | `plugins/base64-payload-wrapper.js` | Free Intruder payload processor |
| BlindSpot Beacon Hunter | `plugins/blindspot-beacon-hunter.js` | Hunter Pro Beacon and findings |
| Fingerprint Flip | `plugins/fingerprint-flip.js` | Transport A/B, Hunter Pro findings |
| Shadow Matrix | `plugins/shadow-matrix.js` | Hunter Pro identity replay and findings |
| SSRF Cannon | `plugins/ssrf-cannon.js` | Hunter Pro Beacon and findings |

## Safety

Only run active plugins against systems you are authorized to test. Use `crusader plugin preview <url>` to inspect requested capabilities before install.

## License

MIT. See `LICENSE`.
