/*!
 * Secret Scanner — a passive scan-check that searches response bodies for high-signal
 * secret formats (AWS keys, Google API keys, Stripe live keys, GitHub/Slack tokens,
 * private-key blocks, JWTs) and raises a Finding per hit.
 *
 * Findings use Crusader's gated finding API, so raising them requires Hunter Pro
 * (the `scanner.findings` capability). The plugin installs on Free. Approve on install.
 *
 * Crusader community plugin · MIT License · https://crusaderproxy.com/ext/secret-scanner.js
 * Install:  crusader plugin install https://crusaderproxy.com/ext/secret-scanner.js
 */
"use strict";

var manifest = {
  id: "secret-scanner",
  name: "Secret Scanner",
  version: "1.0.0",
  capabilities: ["scanner.findings"]
};

var RULES = [
  { name: "AWS access key id", re: /AKIA[0-9A-Z]{16}/ },
  { name: "AWS temporary key id", re: /ASIA[0-9A-Z]{16}/ },
  { name: "Google API key", re: /AIza[0-9A-Za-z_-]{35}/ },
  { name: "Stripe live secret key", re: /sk_live_[0-9A-Za-z]{16,}/ },
  { name: "GitHub token", re: /gh[pousr]_[0-9A-Za-z]{36,}/ },
  { name: "Slack token", re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: "Private key block", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { name: "JSON Web Token", re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/ }
];

crusader.scanCheck({
  name: "Secret Scanner",
  run: function (request, response) {
    var body = response.body;
    if (!body) return;
    for (var i = 0; i < RULES.length; i++) {
      if (RULES[i].re.test(body)) {
        crusader.report({
          severity: "high",
          title: "Possible secret in response: " + RULES[i].name,
          detail: "A value matching the " + RULES[i].name + " pattern appeared in the response body. Confirm it is a live credential before reporting.",
          url: request.url
        });
      }
    }
  }
});
