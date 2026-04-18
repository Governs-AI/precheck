// SPDX-License-Identifier: MIT
// QA.3 — Load regression for precheck.
//
// Drives /api/v1/precheck at 100 req/s for 30s and asserts p95 < 200ms.
//
// Run locally (precheck must be running on PRECHECK_URL):
//   PRECHECK_URL=http://localhost:8082 GOVERNS_KEY=GAI_test_valid_key_12345 \
//     k6 run --summary-export=precheck_load.json precheck_load.js
//
// CI usage: the `load` job in `.github/workflows/ci.yml` boots the precheck
// service on port 8082, runs this script, and uploads `precheck_load.json`
// + `summary.html` as build artefacts.

import http from "k6/http";
import { check } from "k6";

const BASE_URL = __ENV.PRECHECK_URL || "http://localhost:8082";
const API_KEY = __ENV.GOVERNS_KEY || "";

export const options = {
  scenarios: {
    constant_rate: {
      executor: "constant-arrival-rate",
      rate: 100, // 100 iterations per second
      timeUnit: "1s",
      duration: "30s",
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
  },
  thresholds: {
    // QA.3 acceptance criterion: p95 latency must stay under 200ms.
    http_req_duration: ["p(95)<200"],
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
  },
};

const SAMPLES = [
  "hello world, nothing sensitive here",
  "please verify the attached document",
  "send me the report when ready",
  "contact dev@example.com for help",
  "order #A-1729 has shipped",
];

const TOOLS = [
  "verify_identity",
  "send_marketing_email",
  "model.chat",
  "audit_log",
  "data_export",
];

export default function () {
  const body = JSON.stringify({
    tool: TOOLS[Math.floor(Math.random() * TOOLS.length)],
    scope: "local",
    raw_text: SAMPLES[Math.floor(Math.random() * SAMPLES.length)],
  });

  const params = {
    headers: {
      "Content-Type": "application/json",
      "X-Governs-Key": API_KEY,
    },
    tags: { endpoint: "precheck" },
  };

  const res = http.post(`${BASE_URL}/api/v1/precheck`, body, params);

  check(res, {
    "status is 200": (r) => r.status === 200,
    "has decision": (r) => {
      try {
        return typeof r.json("decision") === "string";
      } catch (_e) {
        return false;
      }
    },
  });
}

export function handleSummary(data) {
  return {
    stdout: textSummary(data),
    "precheck_load.json": JSON.stringify(data, null, 2),
    "summary.html": htmlSummary(data),
  };
}

// --- tiny inline summary helpers (no external imports in CI) -----------------

function textSummary(data) {
  const m = data.metrics || {};
  const p95 = m.http_req_duration && m.http_req_duration.values["p(95)"];
  const failed = m.http_req_failed && m.http_req_failed.values.rate;
  const iters = m.iterations && m.iterations.values.count;
  return [
    "",
    "── precheck load summary ─────────────────────────────",
    `  iterations:        ${iters}`,
    `  http p95:          ${p95 !== undefined ? p95.toFixed(2) + " ms" : "n/a"}`,
    `  http_req_failed:   ${failed !== undefined ? (failed * 100).toFixed(2) + " %" : "n/a"}`,
    "──────────────────────────────────────────────────────",
    "",
  ].join("\n");
}

function htmlSummary(data) {
  return (
    "<!doctype html><meta charset='utf-8'><title>precheck load</title>" +
    "<pre style='font:14px ui-monospace,monospace;padding:1rem'>" +
    escapeHtml(JSON.stringify(data.metrics, null, 2)) +
    "</pre>"
  );
}

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
