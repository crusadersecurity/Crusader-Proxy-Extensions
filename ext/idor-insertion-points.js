/*!
 * IDOR Insertion Points — marks numeric IDs and id-like parameters (id, *_id, uid,
 * account, order, ...) in the query and path as extra scanner fuzz points, so
 * Crusader's authorization checks probe object references the default policy may skip.
 * Declares WHERE to fuzz only — it sends no traffic and needs no permissions.
 *
 * Crusader community plugin · MIT License · https://crusaderproxy.com/ext/idor-insertion-points.js
 * Install:  crusader plugin install https://crusaderproxy.com/ext/idor-insertion-points.js
 */
"use strict";

var manifest = {
  id: "idor-insertion-points",
  name: "IDOR Insertion Points",
  version: "1.0.0",
  capabilities: []
};

var ID_NAME = /^(id|.*_id|.*id|uid|guid|uuid|user|userid|account|accountid|customer|order|orderid|invoice|object|objectid|ref|number)$/i;
var NUMERIC = /^\d{1,19}$/;

crusader.onInsertionPoints(function (request) {
  var points = [];

  // id-like or numeric query params
  (request.query || []).forEach(function (q) {
    if (ID_NAME.test(q.name) || NUMERIC.test(q.value || "")) {
      points.push({ kind: "query", name: q.name, location: "idor:query:" + q.name });
    }
  });

  // numeric path segments (e.g. /api/orders/1042)
  var segs = (request.path || "").split("/");
  for (var i = 0; i < segs.length; i++) {
    if (NUMERIC.test(segs[i])) {
      points.push({ kind: "path", index: i, location: "idor:path:" + i });
    }
  }

  return points;
});
