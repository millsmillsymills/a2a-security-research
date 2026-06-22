# PoC #2: Webhook SSRF + Forged Task Completion

## Threat

An A2A agent that fetches push-notification callback URLs without an allow-list
is vulnerable to SSRF (OWASP ASI07). An attacker supplies a loopback or metadata-
endpoint URL as the callback; the agent fetches it server-side and returns the
response. Separately, a task-completion endpoint that accepts state-changing
callbacks without authentication allows any caller to forge a "completed" status.
Together these two weaknesses let an attacker read internal metadata and
manipulate agent task state without authorization.

## Precondition

- The agent fetches any attacker-supplied `callback_url` with no host allow-list.
- The `/tasks/{id}/complete` endpoint accepts JSON payloads with no signature or
  token check.

## Observed Impact

- Loopback metadata contents (e.g. `SECRET=hunter2`) are returned to the attacker
  via the webhook response body.
- Task state is flipped from `working` to `completed` by an unauthenticated POST,
  bypassing any intended authorization flow.

## Control That Closes It

1. **Callback-host allow-list with DNS-rebinding protection** — the secure agent
   parses the callback URL, enforces an `http`/`https` scheme allow-list, and
   rejects any hostname not in an explicit allowset. It then resolves the
   hostname and rejects the request if *any* resolved address is non-global
   (loopback, link-local such as `169.254.169.254`, or private), returning HTTP
   403 before any outbound fetch. IPv6 addresses that embed an IPv4 — IPv4-mapped
   (`::ffff:…`) and the NAT64 well-known prefix (`64:ff9b::/96`) — are vetted by
   their embedded IPv4, since a NAT64 gateway would otherwise route an
   apparently-global address to an internal host. The fetch is pinned to the validated IP (with
   the original `Host` header preserved), so an allow-listed name that rebinds to
   a loopback/metadata address between the check and the fetch cannot reach it.

2. **Task-bound HMAC-signed completions** — the completion endpoint requires an
   `X-A2A-Signature` header containing an HMAC-SHA256 hex digest computed over the
   path `task_id` bound to the raw request body, with a shared secret. Unsigned,
   forged, or wrong-task signatures are rejected with HTTP 401; the task state is
   not modified. Binding the `task_id` stops a completion signed for one task from
   being replayed against another.

## How to Run

```
make demo
```

The demo starts both the vulnerable agent and a local metadata server on
loopback, performs a real SSRF exfiltration and forged completion, then shows the
mitigated agent blocking both attacks. Expected output:

```
[exploit] SSRF exfiltrated via webhook: 'SECRET=hunter2'
[exploit] forged completion accepted: HTTP 200 -> ...
[mitigation] SSRF to loopback blocked: HTTP 403
[mitigation] unsigned completion rejected: HTTP 401
[mitigation] valid signed completion accepted: HTTP 200
OK: SSRF + forged completion demonstrated and mitigated.
```

## Safety Note

All network targets are `127.0.0.1`. No external hosts are contacted. No
third-party infrastructure is involved. Both servers are daemon threads that are
torn down in a `finally` block when the demo process exits; nothing persists after
the run.
