/*!
 * BlindSpot Beacon Hunter — find bugs that never show up in the response.
 *
 * Two roles in one file:
 *   RADAR  (passive): watches live requests, JSON bodies, and WebSocket frames for
 *          server-side-fetch / callback sinks (url, webhook, import, feed, pdf, template…)
 *          and flags each as a candidate finding. Passive hooks can't send traffic, so this
 *          only *spots* sinks — it never fires anything on its own.
 *   PROVER (active): `crusader ext run blindspot-hunter` — mints a per-probe OOB Beacon for
 *          each sink, injects a safe canary URL, polls for callbacks, and ties any hit back to
 *          the exact request/history row. Proves blind SSRF, webhook injection, PDF/XML
 *          renderer fetches, template/email callbacks, and backend job fetches.
 *
 * The demo: the target returns a boring {"ok":true}; five seconds later BlindSpot raises
 * "CRITICAL: backend fetched your canary" with the source endpoint and the callback's origin.
 *
 * Hunter Pro (Beacon hits + findings). Active out-of-band probing — AUTHORIZED TARGETS ONLY.
 * Crusader community plugin · MIT · https://crusaderproxy.com/ext/blindspot-beacon-hunter.js
 */
"use strict";

// High-signal parameter names that tend to drive a server-side fetch or callback.
var SINK = /^(url|uri|link|href|callback|webhook|hook|notify|notify_url|notifyurl|return_url|returnurl|redirect|redirect_uri|redirecturi|next|continue|dest|destination|target|feed|rss|src|source|avatar|image|image_url|imageurl|img|photo|icon|logo|file|file_url|fileurl|fetch|load|import|proxy|forward|host|domain|site|preview|render|pdf|xml|xsl|template|svg|remote|upstream|origin|endpoint|document|attachment|embed|iframe|resource|webhookurl)$/i;
var MAX_BODY = 200000; // don't parse huge bodies in a passive hook

function queryKeys(url) {
  var out = [], qi = (url || "").indexOf("?");
  if (qi < 0) return out;
  var qs = url.slice(qi + 1), hh = qs.indexOf("#");
  if (hh >= 0) qs = qs.slice(0, hh);
  var parts = qs.split("&");
  for (var i = 0; i < parts.length; i++) {
    var eq = parts[i].indexOf("="), k = eq >= 0 ? parts[i].slice(0, eq) : parts[i];
    try { k = decodeURIComponent(k); } catch (e) {}
    if (k) out.push(k);
  }
  return out;
}
function looksJson(s) { s = (s || "").replace(/^\s+/, ""); return s.charAt(0) === "{" || s.charAt(0) === "["; }
function jsonSinkKeys(obj, depth) {
  depth = depth || 0; var out = [];
  if (!obj || typeof obj !== "object" || depth > 2) return out;
  for (var k in obj) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) continue;
    if (typeof obj[k] === "string" && SINK.test(k)) out.push(k);
    if (obj[k] && typeof obj[k] === "object" && depth < 2) {
      var sub = jsonSinkKeys(obj[k], depth + 1);
      for (var j = 0; j < sub.length; j++) out.push(sub[j]);
    }
  }
  return out;
}
function setQueryParam(url, key, value) {
  try {
    var hash = "", h = url.indexOf("#"); if (h >= 0) { hash = url.slice(h); url = url.slice(0, h); }
    var qi = url.indexOf("?"), path = qi >= 0 ? url.slice(0, qi) : url, qs = qi >= 0 ? url.slice(qi + 1) : "";
    var parts = qs ? qs.split("&") : [], enc = encodeURIComponent(value), found = false;
    for (var i = 0; i < parts.length; i++) {
      var eq = parts[i].indexOf("="), k = eq >= 0 ? parts[i].slice(0, eq) : parts[i];
      if (decodeURIComponent(k) === key) { parts[i] = k + "=" + enc; found = true; }
    }
    if (!found) parts.push(encodeURIComponent(key) + "=" + enc);
    return path + "?" + parts.join("&") + hash;
  } catch (e) { return url; }
}
function setJsonParam(body, key, value) {
  try {
    var o = JSON.parse(body);
    if (Object.prototype.hasOwnProperty.call(o, key)) { o[key] = value; }
    else { for (var k in o) { if (o[k] && typeof o[k] === "object" && Object.prototype.hasOwnProperty.call(o[k], key)) { o[k][key] = value; break; } } }
    return JSON.stringify(o);
  } catch (e) { return body; }
}

/* ----------------------------- RADAR (passive) ----------------------------- */
var seen = {};
function flag(method, url, where, param, hid) {
  var base = (url || "").split("?")[0];
  var key = (method || "") + " " + base + " :: " + where + ":" + param;
  if (seen[key]) return; seen[key] = 1;
  crusader.report({
    severity: "info",
    title: "Blind-sink candidate: " + param + " (" + where + ")",
    detail: "'" + param + "' on " + method + " " + url + " looks like a server-side fetch / callback sink. " +
            "Prove it: crusader ext run blindspot-hunter -i history_id=" + (hid || "<id>") + " -i param=" + param,
    url: url
  });
}

crusader.scanCheck({
  name: "BlindSpot radar",
  run: function (request, response) {
    var url = request.url || "", method = request.method || "GET";
    var qk = queryKeys(url);
    for (var i = 0; i < qk.length; i++) { if (SINK.test(qk[i])) flag(method, url, "query", qk[i]); }
    var body = request.body || "";
    if (body && body.length < MAX_BODY && looksJson(body)) {
      try { jsonSinkKeys(JSON.parse(body)).forEach(function (k) { flag(method, url, "json-body", k); }); } catch (e) {}
    }
  }
});

crusader.onWsFrame(function (frame) {
  var txt = frame && (frame.text || frame.payload || frame.data || frame.message);
  if (typeof txt !== "string" || !txt || txt.length >= MAX_BODY || !looksJson(txt)) return;
  try {
    var where = (frame && (frame.url || frame.host)) || "websocket";
    jsonSinkKeys(JSON.parse(txt)).forEach(function (k) { flag("WS", where, "ws-frame", k); });
  } catch (e) {}
});

/* ----------------------------- PROVER (active) ----------------------------- */
crusader.extension({
  id: "blindspot-hunter",
  name: "BlindSpot Beacon Hunter",
  version: "1.0.0",
  description: "Inject OOB canaries into server-side-fetch sinks and prove blind SSRF / webhook / import bugs from the callback.",
  permissions: ["history", "network", "beacon", "findings"],
  capabilities: ["history", "network", "beacon", "scanner.findings"],
  inputs: [
    { id: "history_id", type: "text", label: "History id (blank = auto-scan recent sink-y requests)", default: "" },
    { id: "param", type: "text", label: "Param to inject (blank = auto-detect)", default: "" },
    { id: "wait", type: "text", label: "Seconds to wait for callbacks (5–45)", default: "20" }
  ],
  run: function (state, api) {
    api.ui({ t: "note", level: "warn", text: "Active out-of-band probing — authorized targets only." });
    var wait = Math.max(5, Math.min(45, parseInt(state.wait || "20", 10) || 20));
    var explicitHid = parseInt((state.history_id || "").trim(), 10);
    var explicitParam = (state.param || "").trim();
    var MAX_PROBES = 6, PER_REQ = 3;

    var cands = [];
    function addFromRow(full) {
      if (!full || !full.url) return;
      var added = 0;
      var qk = queryKeys(full.url);
      for (var i = 0; i < qk.length && added < PER_REQ && cands.length < MAX_PROBES; i++) {
        if (explicitParam ? qk[i] === explicitParam : SINK.test(qk[i])) { cands.push({ hid: full.id, method: full.method || "GET", url: full.url, where: "query", param: qk[i] }); added++; }
      }
      var body = full.request_body || full.body || "";
      if (body && looksJson(body)) {
        try {
          var o = JSON.parse(body);
          for (var k in o) {
            if (added >= PER_REQ || cands.length >= MAX_PROBES) break;
            if (typeof o[k] !== "string") continue;
            if (explicitParam ? k === explicitParam : SINK.test(k)) { cands.push({ hid: full.id, method: full.method || "POST", url: full.url, where: "json", param: k, body: body }); added++; }
          }
        } catch (e) {}
      }
    }

    if (explicitHid) {
      addFromRow(api.historyGet(explicitHid));
    } else {
      api.status("Auto-scanning recent history for server-side-fetch sinks…");
      var rows = api.history({ limit: 200 }) || [];
      for (var r = 0; r < rows.length && cands.length < MAX_PROBES; r++) {
        var hot = false, qk = queryKeys(rows[r].url || "");
        for (var q = 0; q < qk.length; q++) { if (SINK.test(qk[q])) hot = true; }
        var m = (rows[r].method || "").toUpperCase();
        if (hot || m === "POST" || m === "PUT" || m === "PATCH") addFromRow(api.historyGet(rows[r].id));
      }
    }

    if (!cands.length) { api.ui({ t: "note", level: "warn", text: "No server-side-fetch sinks found. Pass an explicit history_id + param, or capture traffic with url/webhook/import-style params first." }); return; }

    var probes = [];
    for (var c = 0; c < cands.length; c++) {
      if (api.cancelled()) break;
      var cd = cands[c], tag = "blindspot-" + cd.hid + "-" + cd.param;
      var b = api.beacon({ action: "create", module: "ssrf", tag: tag, historyId: cd.hid });
      if (!b || b.ok === false || !b.host) { api.output("beacon not ready for " + cd.param + ": " + ((b && b.error) || "configure Beacon (Custom/BYO ok)")); continue; }
      var canary = "http://" + b.host + "/";
      var res = cd.where === "query"
        ? api.request({ method: cd.method, url: setQueryParam(cd.url, cd.param, canary), source: "blindspot" })
        : api.request({ method: cd.method, url: cd.url, headers: { "content-type": "application/json" }, body: setJsonParam(cd.body, cd.param, canary), source: "blindspot" });
      api.output("fired " + cd.param + " (" + cd.where + ") on " + cd.method + " " + cd.url + " → HTTP " + (res.status === 0 ? (res.statusText || "blocked") : res.status));
      probes.push({ tag: tag, slug: b.slug, host: b.host, cd: cd });
    }

    if (!probes.length) { api.ui({ t: "note", level: "error", text: "No beacons armed — configure Beacon first (Custom/BYO works on Free)." }); return; }
    api.ui({ t: "summary", title: "BlindSpot Beacon Hunter", subtitle: probes.length + " canaries armed", stats: [{ label: "sinks", value: String(probes.length) }, { label: "wait", value: wait + "s" }] });

    api.status("Waiting up to " + wait + "s for backend callbacks…");
    var slept = 0, anyHit = false, findings = [], pending = probes.slice();
    while (slept < wait && pending.length && !api.cancelled()) {
      api.sleep(2000); slept += 2;
      for (var p = pending.length - 1; p >= 0; p--) {
        var hits = api.beacon({ action: "hits", slug: pending[p].slug, tag: pending[p].tag, limit: 20 }) || [];
        if (!hits.length) continue;
        anyHit = true;
        var http = null;
        for (var h = 0; h < hits.length; h++) { if (/http/i.test(hits[h].protocol || "")) { http = hits[h]; break; } }
        var lead = http || hits[0], cd = pending[p].cd;
        var origin = lead.geo ? (lead.source_ip + " / " + lead.geo) : (lead.source_ip || "unknown source");
        api.report({
          severity: http ? "critical" : "info",
          title: http ? ("CRITICAL: backend fetched your canary (" + (lead.geo || lead.source_ip || "OOB") + ")") : "OOB DNS callback (weak signal)",
          detail: "Injecting '" + cd.param + "' (" + cd.where + ") on " + cd.method + " " + cd.url + " caused an out-of-band " +
                  (lead.protocol || "?") + " request to your canary from " + origin + ", " + slept + "s after the request. " +
                  (http ? "This proves a server-side fetch — blind SSRF / webhook injection / import / renderer." : "DNS-only proves resolution, not a fetch; confirm with an HTTP hit before reporting."),
          url: cd.url, historyId: cd.hid
        });
        findings.push({ severity: http ? "critical" : "info", title: cd.param + " → " + (lead.protocol || "?") + " from " + (lead.source_ip || "?"), url: cd.url, detail: cd.method + " " + cd.url });
        pending.splice(p, 1);
      }
      api.progress({ message: "polling beacons", current: slept, total: wait });
    }

    if (findings.length) api.ui({ t: "findings", subtitle: "Confirmed out-of-band callbacks", items: findings });
    if (!anyHit) api.ui({ t: "note", level: "ok", text: "No callbacks in " + wait + "s across " + probes.length + " sinks. Not proof of safety — try more params, a longer wait (crusader beacon wait), or a Beacon host on the target's egress path." });
  }
});
