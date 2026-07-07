/*!
 * GraphQL Introspection Detector — a passive scan-check that flags GraphQL endpoints
 * whose responses expose the introspection schema (__schema / __type / queryType),
 * leaking the full API surface. Raises one Finding.
 *
 * Findings use Crusader's gated finding API, so raising them requires Hunter Pro
 * (the `scanner.findings` capability). The plugin installs on Free. Approve on install.
 *
 * Crusader community plugin · MIT License · https://crusaderproxy.com/ext/graphql-introspection.js
 * Install:  crusader plugin install https://crusaderproxy.com/ext/graphql-introspection.js
 */
"use strict";

var manifest = {
  id: "graphql-introspection",
  name: "GraphQL Introspection Detector",
  version: "1.0.0",
  capabilities: ["scanner.findings"]
};

crusader.scanCheck({
  name: "GraphQL Introspection Detector",
  run: function (request, response) {
    var body = response.body || "";
    var url = request.url || "";
    var looksGraphql = /graphql|graphiql|\/gql/i.test(url);

    if (!looksGraphql && body.indexOf("__schema") < 0) return;

    if (body.indexOf("\"__schema\"") >= 0 || body.indexOf("\"queryType\"") >= 0 || body.indexOf("\"__type\"") >= 0) {
      crusader.report({
        severity: "medium",
        title: "GraphQL introspection enabled",
        detail: "The GraphQL endpoint returned introspection data (__schema/__type/queryType). Disable introspection in production so the full schema isn't exposed to anonymous clients.",
        url: request.url
      });
    }
  }
});
