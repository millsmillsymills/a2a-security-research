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
# RFC 6052 well-known prefix: a NAT64 gateway maps these to the IPv4 in the low
# 32 bits, so an internal IPv4 reached this way must be vetted as that IPv4.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")


def _is_safe_global(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """An address is safe only if it is global *and* any IPv4 it embeds (via the
    IPv4-mapped form or the NAT64 well-known prefix) is itself global. NAT64
    addresses report ``is_global`` even when they tunnel to a loopback/metadata
    IPv4, so the embedded address is the real check."""
    if not addr.is_global:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = addr.ipv4_mapped
        if embedded is None and addr in _NAT64_WELL_KNOWN:
            embedded = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        if embedded is not None and not embedded.is_global:
            return False
    return True


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
    except (OSError, UnicodeError):
        # gaierror (subclass of OSError) for an unresolvable host, plus UnicodeError
        # for an over-long IDNA label — both fail closed rather than escaping as a 500.
        return None
    addresses = {str(info[4][0]) for info in infos}
    if not addresses or any(not _is_safe_global(ipaddress.ip_address(ip)) for ip in addresses):
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
        netloc = f"[{ip}]:{port}" if ipaddress.ip_address(ip).version == 6 else f"{ip}:{port}"
        pinned_url = parsed._replace(netloc=netloc).geturl()
        try:
            resp = httpx.get(pinned_url, headers={"Host": host}, timeout=2.0)
        except httpx.HTTPError as exc:
            return JSONResponse({"error": f"callback fetch failed: {exc}"}, status_code=502)
        return JSONResponse({"fetched": resp.text})

    async def complete(request: Request) -> JSONResponse:
        raw = await request.body()
        task_id = request.path_params["task_id"]
        provided = request.headers.get("X-A2A-Signature", "")
        if not hmac.compare_digest(provided, sign(task_id, raw, secret)):
            return JSONResponse({"error": "invalid signature"}, status_code=401)
        try:
            status = json.loads(raw)["status"]
        except (json.JSONDecodeError, KeyError, TypeError):
            return JSONResponse(
                {"error": "completion body must be JSON with a 'status' field"}, status_code=400
            )
        TASKS[task_id] = status
        return JSONResponse({"task": task_id, "status": TASKS[task_id]})

    return Starlette(
        routes=[
            Route("/tasks/{task_id}/webhook", webhook, methods=["POST"]),
            Route("/tasks/{task_id}/complete", complete, methods=["POST"]),
        ]
    )
