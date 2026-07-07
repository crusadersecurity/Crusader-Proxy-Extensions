/*!
 * JWT Inspector — adds a "JWT" tab to the request detail view that decodes any Bearer
 * JSON Web Token and shows its header algorithm and claims (read-only). Flags alg=none
 * and expired tokens. Runs entirely locally; no network, no findings, no permissions.
 *
 * Crusader community plugin · MIT License · https://crusaderproxy.com/ext/jwt-inspector.js
 * Install:  crusader plugin install https://crusaderproxy.com/ext/jwt-inspector.js
 */
"use strict";

var manifest = {
  id: "jwt-inspector",
  name: "JWT Inspector",
  version: "1.0.0",
  capabilities: []
};

function decodeSegment(seg) {
  var s = seg.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}

crusader.editorTab({
  title: "JWT",
  request: true,
  response: false,
  render: function (exchange) {
    var raw = (exchange.request && exchange.request.raw) || "";
    var m = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/.exec(raw);
    if (!m) return "No JSON Web Token found in this request.";

    var parts = m[0].split(".");
    var header = null, claims = null;
    try { header = JSON.parse(decodeSegment(parts[0])); } catch (e) {}
    try { claims = JSON.parse(decodeSegment(parts[1])); } catch (e) {}
    if (!claims) return "Found a token but its claims segment did not decode as JSON.";

    var lines = [];
    var alg = header && header.alg ? header.alg : "unknown";
    lines.push("ALGORITHM: " + alg);
    if (String(alg).toLowerCase() === "none") {
      lines.push("WARNING: alg=none — the signature is not verified. Try forging claims.");
    }
    lines.push("");
    lines.push("CLAIMS:");
    lines.push(JSON.stringify(claims, null, 2));
    if (claims.exp) {
      var exp = new Date(claims.exp * 1000);
      lines.push("");
      lines.push("exp: " + exp.toISOString() + (exp < new Date() ? "  (EXPIRED)" : ""));
    }
    return lines.join("\n");
  }
});
