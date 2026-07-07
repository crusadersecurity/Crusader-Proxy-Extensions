/*!
 * Security Header Audit — a passive scan-check that flags HTML responses missing key
 * security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
 * and raises one Finding listing the gaps.
 *
 * Findings are written through Crusader's gated finding API, so raising them requires
 * Hunter Pro (the `scanner.findings` capability). The plugin installs on Free; the
 * findings appear once you're on Pro. Approve the capability on install.
 *
 * Crusader community plugin · MIT License · https://crusaderproxy.com/ext/security-headers.js
 * Install:  crusader plugin install https://crusaderproxy.com/ext/security-headers.js
 */
"use strict";

var manifest = {
  id: "security-headers",
  name: "Security Header Audit",
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
  name: "Security Header Audit",
  run: function (request, response) {
    var ct = (headerValue(response, "content-type") || "").toLowerCase();
    if (ct.indexOf("text/html") < 0) return; // only audit top-level documents

    var missing = [];
    if (!headerValue(response, "content-security-policy")) missing.push("Content-Security-Policy");
    if (!headerValue(response, "strict-transport-security") && (request.url || "").indexOf("https://") === 0) missing.push("Strict-Transport-Security");
    if (!headerValue(response, "x-content-type-options")) missing.push("X-Content-Type-Options");
    if (!headerValue(response, "x-frame-options") && !headerValue(response, "content-security-policy")) missing.push("X-Frame-Options");
    if (!headerValue(response, "referrer-policy")) missing.push("Referrer-Policy");

    if (missing.length) {
      crusader.report({
        severity: "low",
        title: "Missing security headers: " + missing.join(", "),
        detail: "The HTML response did not set: " + missing.join(", ") + ". These reduce defense-in-depth against XSS, clickjacking, and MIME sniffing.",
        url: request.url
      });
    }
  }
});
