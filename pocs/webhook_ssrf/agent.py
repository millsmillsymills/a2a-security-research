"""Vulnerable agent: SSRF via push-notification callback + forged completion."""

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

TASKS: dict[str, str] = {}


def vulnerable_app() -> Starlette:
    async def webhook(request: Request) -> JSONResponse:
        body = await request.json()
        # VULN: fetch any attacker-supplied URL, no allow-list.
        resp = httpx.get(body["callback_url"], timeout=2.0)
        return JSONResponse({"fetched": resp.text})

    async def complete(request: Request) -> JSONResponse:
        task_id = request.path_params["task_id"]
        body = await request.json()
        # VULN: no authentication on state-changing callback.
        TASKS[task_id] = body["status"]
        return JSONResponse({"task": task_id, "status": TASKS[task_id]})

    return Starlette(
        routes=[
            Route("/tasks/{task_id}/webhook", webhook, methods=["POST"]),
            Route("/tasks/{task_id}/complete", complete, methods=["POST"]),
        ]
    )
