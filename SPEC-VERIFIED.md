# Spec Verification Record

**A2A spec version verified against:** v1.0.0
**Date verified:** 2026-06-17
**Sources:**
- Specification: https://a2a-protocol.org/v1.0.0/specification/
- Agent discovery (well-known path): https://a2a-protocol.org/v1.0.0/topics/agent-discovery/
- SDK: `a2a-sdk==1.1.0` (PyPI; implements A2A spec 1.0, compat mode for 0.3)

| Item | Verified value |
|------|----------------|
| Agent Card well-known path | `/.well-known/agent-card.json` (RFC 8615) |
| Protocol version string format | `Major.Minor` (e.g. `1.0`); patch not used in cards/requests; transmitted via the `A2A-Version` service parameter (header/param) |
| Per-interface version | `AgentInterface.protocol_version` (e.g. `"1.0"`) — version negotiation is per interface; there is **no** `protocol_version` field on `AgentCard` itself |
| Card auth declaration | `security_schemes` (JSON: `securitySchemes`) — a map of scheme name → scheme |
| Card transport declaration | `supported_interfaces[]` — each `AgentInterface` has `url`, `protocol_binding`, `protocol_version`, `tenant` |
| Card signature object | `AgentCardSignature` (spec §4.4.7); `AgentCard.signatures[]`; JWS over JCS-canonicalized content (spec §8.4). Proto fields: `protected`, `signature`, `header` (JWS detached form) |

## SDK shape (critical — verified by introspection)

`a2a-sdk==1.1.0` `a2a.types.*` are **protobuf messages** (`google._upb._message`), **not** pydantic models. Consequences for all code:

- Construct with keyword args using the proto field names below.
- Serialize to JSON with `google.protobuf.json_format.MessageToJson(msg)` — **not** `msg.model_dump_json()`. There is no `model_dump_json`, `model_fields`, or `model_json_schema`.
- Proto3 defaults: unset scalars are `""`/`0`/`False` (not `None`); `MessageToJson` omits default-valued and empty-repeated fields by default.

Re-verify all of the above before any future build — A2A and its SDK iterate quickly.
