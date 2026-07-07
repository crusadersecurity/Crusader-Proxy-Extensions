/*!
 * CORS Auditor — a passive scan-check that flags risky CORS responses: wildcard
 * Access-Control-Allow-Origin with credentials, an Origin reflected with credentials,
 * and an allowed "null" origin. Raises a Finding per issue.
 *
 * Findings use Crusader's gated finding API, so raising them requires Hunter Pro
 * (the `scanner.findings` capability). The plugin installs on Free. Approve on install.
 *
 * Crusader community plugin · MIT License · https://crusaderproxy.com/ext/cors-auditor.js
 * Install:  crusader plugin install https://crusaderproxy.com/ext/cors-auditor.js
 */
"use strict";

var manifest = {
  id: "cors-auditor",
  name: "CORS Auditor",
  version: "1.0.0",
  capabilities: ["scanner.findings"]
};

function headerValue(message, name) {
  var h = (message && message.headers) || {};
  var keys = Object.keys(h);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === name) return h[keys[i]];
  }
  return null;
}

crusader.scanCheck({
  name: "CORS Auditor",
  run: function (request, response) {
    var acao = headerValue(response, "access-control-allow-origin");
    if (!acao) return;

    var withCreds = (headerValue(response, "access-control-allow-credentials") || "").toLowerCase() === "true";
    var origin = headerValue(request, "origin");
    var issue = null, severity = "low";

    if (acao === "*" && withCreds) {
      issue = "wildcard Access-Control-Allow-Origin with credentials";
      severity = "high";
    } else if (acao.toLowerCase() === "null") {
      issue = "the 'null' origin is allowed";
      severity = "medium";
    } else if (origin && acao === origin && withCreds) {
      issue = "the request Origin is reflected with credentials";
      severity = "high";
    }

    if (issue) {
      crusader.report({
        severity: severity,
        title: "CORS misconfiguration: " + issue,
        detail: "Access-Control-Allow-Origin: " + acao + (withCreds ? "; Access-Control-Allow-Credentials: true" : "") + ". A cross-origin site may be able to read authenticated responses.",
        url: request.url
      });
    }
  }
});
