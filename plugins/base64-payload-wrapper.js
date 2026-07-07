/*!
 * Base64 Payload Wrapper — an Intruder payload processor that Base64-encodes every
 * payload after the built-in rule chain, for endpoints that expect Base64-wrapped input
 * (e.g. a JSON field or cookie that holds an encoded blob). No permissions needed.
 *
 * Crusader community plugin · MIT License · https://crusaderproxy.com/ext/base64-payload-wrapper.js
 * Install:  crusader plugin install https://crusaderproxy.com/ext/base64-payload-wrapper.js
 */
"use strict";

var manifest = {
  id: "base64-payload-wrapper",
  name: "Base64 Payload Wrapper",
  version: "1.0.0",
  capabilities: []
};

crusader.payloadProcessor(function (payload, ctx) {
  if (payload === null || payload === undefined) return payload;
  try {
    return btoa(String(payload));
  } catch (e) {
    // btoa throws on characters outside Latin-1; leave the payload unchanged.
    return payload;
  }
});
