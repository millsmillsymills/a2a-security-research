# pocs/webhook_ssrf/mitigation.py
"""Mitigation: callback-host allow-list (kills SSRF) + HMAC-signed completion."""

import hmac
import json
from hashlib import sha256
from urllib.parse import urlparse

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from pocs.webhook_ssrf.agent import TASKS


def sign(body: bytes, secret: bytes) -> str:
    return hmac.new(secret, body, sha256).hexdigest()


def secure_app(*, allowed_hosts: set[str], secret: bytes) -> Starlette:
    async def webhook(request: Request) -> JSONResponse:
        body = await request.json()
        host = urlparse(body["callback_url"]).hostname or ""
        if host not in allowed_hosts:
            return JSONResponse({"error": "callback host not allow-listed"}, status_code=403)
        resp = httpx.get(body["callback_url"], timeout=2.0)
        return JSONResponse({"fetched": resp.text})

    async def complete(request: Request) -> JSONResponse:
        raw = await request.body()
        provided = request.headers.get("X-A2A-Signature", "")
        if not hmac.compare_digest(provided, sign(raw, secret)):
            return JSONResponse({"error": "invalid signature"}, status_code=401)
        task_id = request.path_params["task_id"]
        TASKS[task_id] = json.loads(raw)["status"]
        return JSONResponse({"task": task_id, "status": TASKS[task_id]})

    return Starlette(
        routes=[
            Route("/tasks/{task_id}/webhook", webhook, methods=["POST"]),
            Route("/tasks/{task_id}/complete", complete, methods=["POST"]),
        ]
    )
