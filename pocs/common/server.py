"""Serve a spec-valid Agent Card at the v1.0 well-known path, locally only.

Card is a protobuf message; serialize with json_format.MessageToJson, not
model_dump_json (see docs/sdk-surface.md).
"""

import uvicorn
from a2a.types import AgentCard
from google.protobuf import json_format
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

WELL_KNOWN_PATH = "/.well-known/agent-card.json"


class _HstsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=63072000"
        return response


def build_app(card: AgentCard) -> Starlette:
    async def serve_card(_: Request) -> Response:
        return Response(
            content=json_format.MessageToJson(card),
            media_type="application/json",
        )

    return Starlette(
        routes=[Route(WELL_KNOWN_PATH, serve_card, methods=["GET"])],
        middleware=[Middleware(_HstsMiddleware)],
    )


def serve(card: AgentCard, host: str, port: int) -> None:
    uvicorn.run(build_app(card), host=host, port=port, log_level="warning")
