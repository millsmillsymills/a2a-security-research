"""A local stand-in for a cloud metadata endpoint — the SSRF target."""

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route


def metadata_app() -> Starlette:
    async def secret(_: Request) -> PlainTextResponse:
        return PlainTextResponse("SECRET=hunter2")

    return Starlette(routes=[Route("/latest/meta-data/secret", secret)])
