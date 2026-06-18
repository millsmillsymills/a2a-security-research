# pocs/webhook_ssrf/mitigation.py
"""Mitigation: callback-host allow-list (kills SSRF) + HMAC-signed completion."""

import hmac
import ipaddress
import json
import socket
from hashlib import sha256
from urllib.parse import urlparse

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from pocs.webhook_ssrf.agent import TASKS

ALLOWED_SCHEMES = {"http", "https"}


def sign(task_id: str, body: bytes, secret: bytes) -> str:
    """HMAC-SHA256 binding ``task_id`` to the raw body, so a completion signed for
    one task cannot be replayed against another."""
    return hmac.new(secret, task_id.encode() + b"\n" + body, sha256).hexdigest()


def _resolve_pinned_ip(hostname: str, port: int) -> str | None:
    """Resolve ``hostname`` and return one global IP to connect to, or ``None`` if
    it does not resolve or any resolved address is non-global (loopback,
    link-local, private). Pinning the fetch to this IP closes the DNS-rebinding
    gap between the allow-list check and the outbound request."""
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    addresses = {str(info[4][0]) for info in infos}
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        return None
    return next(iter(addresses))


def secure_app(*, allowed_hosts: set[str], secret: bytes) -> Starlette:
    async def webhook(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse({"error": "request body is not valid JSON"}, status_code=400)
        callback_url = body.get("callback_url")
        if not isinstance(callback_url, str):
            return JSONResponse({"error": "missing callback_url"}, status_code=400)
        parsed = urlparse(callback_url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            return JSONResponse({"error": "callback scheme not allow-listed"}, status_code=403)
        host = parsed.hostname or ""
        if host not in allowed_hosts:
            return JSONResponse({"error": "callback host not allow-listed"}, status_code=403)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ip = _resolve_pinned_ip(host, port)
        if ip is None:
            return JSONResponse(
                {"error": "callback host resolves to a non-global address"}, status_code=403
            )
        pinned_url = parsed._replace(netloc=f"{ip}:{port}").geturl()
        resp = httpx.get(pinned_url, headers={"Host": host}, timeout=2.0)
        return JSONResponse({"fetched": resp.text})

    async def complete(request: Request) -> JSONResponse:
        raw = await request.body()
        task_id = request.path_params["task_id"]
        provided = request.headers.get("X-A2A-Signature", "")
        if not hmac.compare_digest(provided, sign(task_id, raw, secret)):
            return JSONResponse({"error": "invalid signature"}, status_code=401)
        TASKS[task_id] = json.loads(raw)["status"]
        return JSONResponse({"task": task_id, "status": TASKS[task_id]})

    return Starlette(
        routes=[
            Route("/tasks/{task_id}/webhook", webhook, methods=["POST"]),
            Route("/tasks/{task_id}/complete", complete, methods=["POST"]),
        ]
    )
