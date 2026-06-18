# a2a-sdk surface (verified 2026-06-17)

Installed: **`a2a-sdk[http-server]==1.1.0`** (pulls `protobuf`, `proto-plus`, `starlette==1.3.1`, `sse-starlette`, `httpx==0.28.1`).

## Types are protobuf, not pydantic

`a2a.types.*` are protobuf messages. Build with kwargs; serialize with `json_format`:

```python
import a2a.types as t
from google.protobuf import json_format

card = t.AgentCard(name="...", description="...", version="1.0.0",
                   supported_interfaces=[t.AgentInterface(url="http://127.0.0.1:9101",
                                                          protocol_binding="JSONRPC",
                                                          protocol_version="1.0")],
                   capabilities=t.AgentCapabilities(streaming=False),
                   skills=[t.AgentSkill(id="fx", name="FX", description="...",
                                        tags=["finance"], examples=["..."])])
body = json_format.MessageToJson(card)  # NOT card.model_dump_json()
```

## Verified field names (proto, snake_case)

| Type | Fields |
|------|--------|
| `AgentCard` | `name`, `description`, `supported_interfaces`, `provider`, `version`, `documentation_url`, `capabilities`, `security_schemes`, `security_requirements`, `default_input_modes`, `default_output_modes`, `skills`, `signatures`, `icon_url` |
| `AgentInterface` | `url`, `protocol_binding`, `tenant`, `protocol_version` |
| `AgentSkill` | `id`, `name`, `description`, `tags`, `examples`, `input_modes`, `output_modes`, `security_requirements` |
| `AgentCapabilities` | `streaming`, `push_notifications`, `extensions`, `extended_agent_card` |
| `AgentCardSignature` | `protected`, `signature`, `header` |

**`AgentCard` has no `protocol_version` field** — set version per interface (`AgentInterface.protocol_version`).

`security_schemes` is a proto map (name → scheme); omit it or pass populated entries (an empty map serializes to nothing).

## Server route factories

`a2a.server.routes` exposes: `create_agent_card_routes`, `create_jsonrpc_routes`, `create_rest_routes`, `add_a2a_routes_to_fastapi` (and `*_routes`/`*_dispatcher` helpers). The v0.3 `A2AStarletteApplication` wrapper is gone. For PoCs, serving the card via a plain Starlette `Route` returning `json_format.MessageToJson(card)` with `Content-Type: application/json` is sufficient and fully verified; use `create_agent_card_routes(card)` only if you want the SDK's exact route behavior.
