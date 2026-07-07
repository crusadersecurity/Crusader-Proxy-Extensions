/*!
 * Fingerprint Flip — JA3 / TLS WAF-bypass A/B.
 *
 * Replays a request on the default transport vs a real browser TLS fingerprint
 * (curl-impersonate) and shows the delta. If the WAF/anti-bot blocks the default but lets
 * the browser fingerprint through, it keys on your TLS fingerprint, not the request — a weak
 * control any impersonation library walks past. Raises a finding when the bypass is confirmed.
 *
 * Burp has no TLS/JA3 impersonation — it literally can't run this test. The A/B is Free
 * (needs the curl-impersonate sidecar on PATH); raising the Finding needs Hunter Pro.
 * Authorized targets only.
 * Crusader community plugin · MIT · https://crusaderproxy.com/ext/fingerprint-flip.js
 */
"use strict";

function fmt(label, r) {
  var ok = r && r.status >= 200 && r.status < 300;
  var text = (r && r.status) ? ("HTTP " + r.status + ", " + (r.size || 0) + "b") : (r && r.error ? r.error : "blocked");
  return { count: ok ? 1 : 0, url: label + "  →  " + text };
}

crusader.extension({
  id: "fingerprint-flip",
  name: "Fingerprint Flip",
  version: "1.0.0",
  description: "Replay a request on the default transport vs a real browser JA3 fingerprint and flag TLS-based WAF bypass.",
  permissions: ["history", "network", "transport", "findings"],
  capabilities: ["history", "network", "transport", "scanner.findings"],
  inputs: [
    { id: "history_id", type: "text", label: "History id of the (blocked?) request", required: true },
    { id: "profile", type: "select", label: "Browser fingerprint", default: "chrome120", options: ["chrome120", "ff117", "safari15_5", "edge101", "chrome99_android"] }
  ],
  run: function (state, api) {
    var hid = parseInt((state.history_id || "").trim(), 10);
    if (!hid) { api.ui({ t: "note", level: "error", text: "Provide a numeric history_id." }); return; }
    var base = api.historyGet(hid);
    if (!base || !base.url) { api.ui({ t: "note", level: "error", text: "No history row " + hid + "." }); return; }
    var method = base.method || "GET", url = base.url, profile = state.profile || "chrome120";
    api.ui({ t: "note", level: "warn", text: "Replays a live request — authorized targets only." });

    var caps = (api.transport && api.transport.capabilities) ? api.transport.capabilities() : null;
    if (caps && caps.native_sidecar_available === false) {
      api.ui({ t: "note", level: "warn", text: "No curl-impersonate sidecar found — using the managed transport (not a true JA3). Install the sidecar for a real fingerprint." });
    }

    api.status("Default transport…");
    var a = api.request({ method: method, url: url, source: "fp-flip-default" });

    api.status("Browser fingerprint (" + profile + ")…");
    var b = api.transport.request({ method: method, url: url, transport: "curl-impersonate", profile: profile, source: "fp-flip-" + profile });

    api.ui({ t: "summary", title: "Fingerprint Flip", subtitle: method + " " + url, stats: [
      { label: "default", value: (a && a.status) ? String(a.status) : "—" },
      { label: profile, value: (b && b.status) ? String(b.status) : "—" },
      { label: "transport", value: (caps && caps.native_sidecar_available) ? "native JA3" : "managed" }
    ] });
    api.ui({ t: "list", title: "Transport A/B", variant: "list", rows: [fmt("default transport", a), fmt(profile + " JA3", b)] });

    var blocked = a && (a.status === 403 || a.status === 429 || a.status === 503 || a.status === 0);
    var through = b && b.status >= 200 && b.status < 400;
    if (blocked && through) {
      var msg = "The default transport was blocked (" + (a.status || a.statusText || "0") + ") but a " + profile +
                " TLS fingerprint got through (" + b.status + "). The control keys on the TLS fingerprint, not the request — an attacker bypasses it with any impersonation library.";
      var gate = api.license({ action: "require", feature: "AdvancedPluginApis" });
      if (gate && gate.ok) {
        api.report({ severity: "medium", title: "WAF / anti-bot bypassed by TLS fingerprint impersonation", detail: msg, url: url, historyId: hid });
        api.ui({ t: "note", level: "warn", text: "Bypass confirmed — finding raised." });
      } else {
        api.ui({ t: "note", level: "warn", text: "Bypass confirmed. (Raising a Finding needs Hunter Pro — the A/B result above is yours on Free.)" });
      }
    } else {
      api.ui({ t: "note", level: "ok", text: "No TLS-fingerprint bypass on this request." });
    }
  }
});
