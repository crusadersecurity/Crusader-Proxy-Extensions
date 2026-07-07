/*!
 * Shadow Matrix — cross-identity access-control matrix (auto-IDOR/BOLA).
 *
 * Takes ONE captured request and replays it as every saved identity that's legally
 * replayable to that URL, plus unauthenticated, then diffs the responses. Anonymous
 * access or two identities seeing the same object jump out as findings.
 *
 * Burp needs the Autorize extension for this; Crusader does it natively off the identity
 * model, refuses out-of-scope / non-replayable identities, and is drivable from the CLI
 * and an AI agent: `crusader ext run shadow-matrix -i history_id=1042`.
 *
 * Hunter Pro (Identity Shadow Replay + findings). Authorized targets only.
 * Crusader community plugin · MIT · https://crusaderproxy.com/ext/shadow-matrix.js
 */
"use strict";

function countOk(arr) { var n = 0; for (var i = 0; i < arr.length; i++) { if (arr[i].ok) n++; } return n; }

crusader.extension({
  id: "shadow-matrix",
  name: "Shadow Matrix",
  version: "1.0.0",
  description: "Replay one captured request as every saved identity and diff the responses to surface IDOR/BOLA.",
  permissions: ["history", "identity", "network", "findings"],
  capabilities: ["history", "identity.signed-replay", "network", "scanner.findings"],
  inputs: [
    { id: "history_id", type: "text", label: "History id of the request to test", required: true, placeholder: "e.g. 1042" },
    { id: "include_unauth", type: "checkbox", label: "Also replay unauthenticated", default: "true" }
  ],
  run: function (state, api) {
    var hid = parseInt((state.history_id || "").trim(), 10);
    if (!hid) { api.ui({ t: "note", level: "error", text: "Provide a numeric history_id (run: crusader history list)." }); return; }

    var base = api.historyGet(hid);
    if (!base || !base.url) { api.ui({ t: "note", level: "error", text: "No history row " + hid + "." }); return; }
    var method = base.method || "GET", url = base.url;
    api.ui({ t: "note", level: "warn", text: "Cross-identity replay — authorized targets only." });

    var ids = api.identities({ url: url }) || [];
    var actors = [];
    for (var i = 0; i < ids.length; i++) {
      if (ids[i].replayable_to_url === true) {
        actors.push({ id: ids[i].id, label: ids[i].label || ids[i].alias || ids[i].name || String(ids[i].id), identity: true });
      }
    }
    if (String(state.include_unauth) !== "false") actors.push({ id: null, label: "unauthenticated", identity: false });
    if (!actors.length) { api.ui({ t: "note", level: "warn", text: "No identities are replayable to this URL. Capture two accounts on the Identities page first." }); return; }

    var results = [];
    for (var j = 0; j < actors.length; j++) {
      if (api.cancelled()) break;
      var a = actors[j];
      api.status("Replaying as " + a.label);
      var res = a.identity
        ? api.requestAs(a.id, { method: method, url: url })
        : api.request({ method: method, url: url, applyActiveIdentity: false });
      var ok2xx = res && res.status >= 200 && res.status < 300;
      var sig = (!res || res.status === 0) ? "blocked" : (res.status + ":" + (Math.round((res.size || 0) / 32) * 32));
      results.push({ label: a.label, identity: a.identity, status: res ? res.status : 0, statusText: res ? res.statusText : "", size: res ? (res.size || 0) : 0, ok: ok2xx, sig: sig });
    }

    api.ui({ t: "summary", title: "Shadow Matrix", subtitle: method + " " + url, stats: [
      { label: "actors", value: String(results.length) },
      { label: "got 2xx", value: String(countOk(results)) }
    ] });
    var rows = [];
    for (var r = 0; r < results.length; r++) {
      var x = results[r];
      rows.push({ count: x.ok ? 1 : 0, url: x.label + "  →  " + (x.status === 0 ? (x.statusText || "blocked") : ("HTTP " + x.status + ", " + x.size + "b")) });
    }
    api.ui({ t: "list", title: "Who sees what", variant: "list", rows: rows });

    var anon = null, sharedSig = null, sigCount = {};
    for (var k = 0; k < results.length; k++) {
      var y = results[k];
      if (!y.identity && y.ok) anon = y;
      if (y.ok) { sigCount[y.sig] = (sigCount[y.sig] || 0) + 1; if (sigCount[y.sig] >= 2) sharedSig = y.sig; }
    }

    if (anon) {
      api.report({ severity: "high", title: "Anonymous access to a request that carried an identity",
        detail: "Replaying " + method + " " + url + " with no credentials returned HTTP " + anon.status + ". If this resource is meant to be authenticated, that's broken access control. Confirm the body isn't a generic/empty page.",
        url: url, historyId: hid });
      api.ui({ t: "note", level: "warn", text: "Unauthenticated request succeeded — finding raised." });
    } else if (sharedSig) {
      api.report({ severity: "medium", title: "Possible IDOR/BOLA: multiple identities receive an identical response",
        detail: "Two or more different identities got the same 2xx response signature for " + method + " " + url + ". If this object should be scoped to one account, that's broken object-level authorization. Confirm the bodies expose another actor's data (try Comparer).",
        url: url, historyId: hid });
      api.ui({ t: "note", level: "warn", text: "Response drift detected — finding raised. Eyeball the bodies to confirm a real leak." });
    } else {
      api.ui({ t: "note", level: "ok", text: "No obvious access-control drift across identities. Subtle leaks still need a manual body diff." });
    }
  }
});
