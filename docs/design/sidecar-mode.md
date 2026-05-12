# Sidecar / Proxy Gateway (Mode 2)

Status: design only for GOV-563 / TASKS.md 2.1a. No implementation is included in this change.

## Goal

Provide a drop-in gateway that sits between an application and the upstream OpenAI-compatible API, runs `precheck` before the request leaves the workload, and preserves normal OpenAI client behavior with only a base URL override.

## Non-Goals

- Implementing the proxy in this issue
- Supporting every OpenAI endpoint on day one
- Building the human approval UX for `confirm`
- Replacing the existing direct-to-`precheck` integration used by the SDK

## Recommended Language

Go is the recommended implementation language for Mode 2.

| Option | Strengths | Tradeoffs | Decision |
| --- | --- | --- | --- |
| Go | Low-overhead concurrency, strong streaming support, mature reverse proxy tooling, single static binary, small container footprint | Less shared code with the Python `precheck` service | Recommended |
| Node.js | Good HTTP ecosystem, familiar for dashboard-adjacent teams | Higher heap pressure for long-lived streaming connections, weaker fit for a hot proxy path, larger runtime surface | Not selected |
| Python | Shared language with `precheck`, easy policy-contract reuse | Weakest fit for a latency-sensitive proxy, more care needed around async streaming and worker scaling | Not selected |

The deciding factor is that the sidecar is a network hot path, not a policy engine. That makes predictable proxy throughput and simple deployment more important than language reuse.

## Deployment Model

The sidecar runs next to the application workload and forwards requests to the upstream model provider.

```text
Application -> Sidecar proxy -> Precheck -> Upstream OpenAI API
```

Expected client configuration:

- Application sets `OPENAI_BASE_URL=http://sidecar:8081/v1`
- Application keeps using a standard OpenAI client library
- Application continues to send the upstream `Authorization: Bearer ...` header
- Sidecar uses its own GovernsAI credentials when calling `precheck`

The sidecar should expose `/v1/*` so OpenAI SDKs can be pointed at it without request-shape changes.

## Request Handling Model

### Intercepted Route

Mode 2 actively intercepts:

- `POST /v1/chat/completions`

All other `/v1/*` routes should be transparent pass-through in the first implementation. That keeps the proxy usable as a general OpenAI base URL while constraining governance logic to one endpoint.

### Why `chat/completions` First

- It is the highest-volume compatibility target across current OpenAI client libraries.
- It matches the issue scope exactly.
- It keeps Phase 2 implementation bounded before adding `responses`, `embeddings`, or tool-call-aware egress controls.

## Proxy Flow

1. Accept `POST /v1/chat/completions`.
2. Parse the JSON body and extract text-bearing message content from `messages`.
3. For each text segment, call `precheck` before any upstream request is sent.
4. Combine segment-level decisions into one request-level outcome.
5. If the request is allowed, forward the original or rewritten body to the upstream target.
6. Relay the upstream response back to the caller unchanged, including SSE streaming when `stream=true`.

### Text Extraction Rule

Phase 2 should treat each text-bearing message segment as an independent unit:

- `messages[].content` when it is a string
- `messages[].content[*].text` when content is an array of typed parts and `type=="text"`

This is deliberate. The current `precheck` API accepts a single `raw_text` string, so per-segment evaluation avoids lossy transcript flattening and makes rewrite placement deterministic.

### Precheck Request Shape

For each extracted text segment, the sidecar sends:

```json
{
  "tool": "openai.chat.completions",
  "scope": "net.external",
  "raw_text": "<segment text>",
  "corr_id": "<request id>:<segment index>"
}
```

Headers sent to `precheck`:

- `X-Governs-Key: <configured Governs API key>`

The sidecar should also include the configured org identifier in structured logs and metrics so decisions can be tied back to the tenant even if `precheck` itself only authenticates with the API key.

## Request-Level Decision Rules

`precheck` currently returns `allow`, `transform`, `confirm`, or `deny`. In the sidecar design, `transform` is the concrete mechanism used to implement redaction or tokenization.

Segment results are combined with this precedence:

1. `deny`
2. `confirm`
3. `transform`
4. `allow`

That means:

- If any segment is `deny`, the whole upstream request is blocked.
- Else if any segment is `confirm`, the whole request is held for confirmation.
- Else if any segment is `transform`, the request is rewritten and forwarded.
- Else the original request is forwarded unchanged.

To avoid partial policy application, the sidecar should stage all rewrites in memory and only mutate the request body after every segment precheck succeeds.

## HTTP Behavior Mapping

| Precheck outcome | Sidecar behavior | HTTP result |
| --- | --- | --- |
| `allow` | Forward request body unchanged | Upstream response is proxied as-is |
| `transform` (`redact` / `tokenize`) | Rewrite affected message segments with `raw_text_out`, then forward | Upstream response is proxied as-is |
| `confirm` | Do not call upstream; return an OpenAI-style error body | `409 Conflict` |
| `deny` | Do not call upstream; return an OpenAI-style error body | `403 Forbidden` |

Recommended error body for blocked requests:

```json
{
  "error": {
    "message": "Request blocked by governance policy.",
    "type": "invalid_request_error",
    "param": null,
    "code": "governance_denied"
  }
}
```

Recommended error body for `confirm` in Phase 2:

```json
{
  "error": {
    "message": "Request requires governance approval before it can be sent upstream.",
    "type": "invalid_request_error",
    "param": null,
    "code": "governance_confirm"
  }
}
```

`confirm` is intentionally a stub in Phase 2. Phase 3 can replace the direct `409` response with an approval handle or async resume flow.

## Configuration Interface

The sidecar should be configured entirely through environment variables or equivalent deployment-time config.

| Variable | Required | Example | Purpose |
| --- | --- | --- | --- |
| `SIDECAR_LISTEN_ADDR` | No | `0.0.0.0:8081` | Bind address for the sidecar |
| `SIDECAR_TARGET_URL` | Yes | `https://api.openai.com` | Upstream OpenAI-compatible API origin |
| `SIDECAR_PRECHECK_URL` | Yes | `http://precheck:8080/api/v1/precheck` | Precheck endpoint used before forwarding |
| `SIDECAR_GOVERNS_ORG_ID` | Yes | `org_123` | Tenant identifier used for logs, metrics, and future policy selection |
| `SIDECAR_GOVERNS_API_KEY` | Yes | `GAI_...` | Credential used to call `precheck` |
| `SIDECAR_PRECHECK_TIMEOUT_MS` | No | `1500` | Timeout for each precheck call |
| `SIDECAR_UPSTREAM_TIMEOUT_MS` | No | `60000` | Timeout for the upstream request |
| `SIDECAR_FAILURE_MODE` | No | `fail_closed` | `fail_closed` or `fail_open` when `precheck` is unavailable |
| `SIDECAR_MAX_BODY_BYTES` | No | `1048576` | Request size cap to protect the proxy |
| `SIDECAR_LOG_LEVEL` | No | `info` | Runtime logging level |

Configuration rules:

- `SIDECAR_TARGET_URL` must not include `/v1`; the proxy owns the `/v1/*` surface.
- `SIDECAR_PRECHECK_URL` should point to the existing `/api/v1/precheck` endpoint.
- `SIDECAR_FAILURE_MODE` defaults to `fail_closed` for enterprise deployments.
- The sidecar must never forward `SIDECAR_GOVERNS_API_KEY` to the upstream model provider.

## OpenAI Drop-In Compatibility

Mode 2 only works if ordinary OpenAI SDKs can talk to the sidecar without custom client code.

Compatibility rules:

- Preserve the upstream path shape under `/v1/*`.
- Preserve the request and response JSON format expected by OpenAI SDKs.
- Preserve SSE framing for `stream=true`.
- Forward the caller's `Authorization` header unchanged to the upstream target.
- Do not require custom headers from the application in the initial version.
- Return OpenAI-style error bodies for governance blocks so client libraries surface predictable exceptions.

Example Python client configuration:

```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-live-upstream",
    base_url="http://localhost:8081/v1",
)
```

The only client-visible change is the base URL.

## Failure Modes

### Precheck Unreachable

This includes connection failures, DNS failures, and timeouts calling `SIDECAR_PRECHECK_URL`.

#### `fail_closed`

- Do not call upstream.
- Return `503 Service Unavailable`.
- Use an OpenAI-style error body with code `precheck_unavailable`.
- Emit an error metric and structured log event.

Recommended body:

```json
{
  "error": {
    "message": "Governance precheck is unavailable.",
    "type": "service_unavailable_error",
    "param": null,
    "code": "precheck_unavailable"
  }
}
```

#### `fail_open`

- Skip the governance decision for that request.
- Forward the original request body unchanged.
- Emit a high-severity log and counter so bypass volume is visible immediately.

`fail_open` must never forward a partially rewritten request. The request is either fully governed or fully bypassed.

### Invalid Client Request

- Malformed JSON or an invalid OpenAI request body returns `400 Bad Request`.
- The sidecar should fail before calling either `precheck` or upstream when parsing fails locally.

### Upstream Unreachable

- Connection failure to `SIDECAR_TARGET_URL` returns `502 Bad Gateway`.
- Upstream timeout returns `504 Gateway Timeout`.
- Upstream HTTP errors are proxied through unchanged when a valid upstream response exists.

## Observability Requirements

The implementation should emit:

- Request count by route and outcome
- Precheck latency histogram
- Upstream latency histogram
- Governance bypass count for `fail_open`
- Rewrite count for `transform`
- Block count for `deny` and `confirm`

Structured logs should include:

- `org_id`
- request correlation ID
- upstream model name when present
- final decision
- failure mode used

Raw prompts must not be logged.

## Security Notes

- GovernsAI credentials are sidecar-only secrets and must not be accepted from the client.
- The upstream OpenAI API key remains the caller's credential and is forwarded unchanged.
- Request rewriting must be limited to text fields that were explicitly evaluated.
- Maximum body size must be enforced before buffering the request in memory.

## Implementation Guidance for 2.1b

The implementation issue should keep the first slice narrow:

1. Build Go proxy with `/v1/chat/completions` interception and `/v1/*` pass-through.
2. Support non-streaming and streaming upstream responses.
3. Support per-segment precheck on message text only.
4. Ship `fail_closed` first, then add `fail_open` as a configuration switch.
5. Add conformance tests using unmodified OpenAI Python and Node clients with a base URL override.

That path keeps Mode 2 compatible with the current `precheck` contract while leaving room for a future batched precheck API.
