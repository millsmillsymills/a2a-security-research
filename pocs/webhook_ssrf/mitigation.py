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
# IPv6 prefixes that carry an IPv4 in their low 32 bits and that ``is_global``
# reports global even when the embedded IPv4 is internal — so the embedded IPv4
# must be re-checked. ``ipv4_mapped``/``sixtofour`` handle the IPv4-mapped and
# 6to4 forms (already non-global when they embed an internal IPv4, but vetted
# anyway). Operator-chosen NAT64 prefixes (RFC 6052 §2.2) and translation
# prefixes inside a globally-assigned allocation are not enumerable from the
# address alone and remain out of scope; defense there belongs at egress.
_LOW32_EMBEDDING_NETS = (
    ipaddress.ip_network("64:ff9b::/96"),  # RFC 6052 NAT64 well-known
    ipaddress.ip_network("::ffff:0:0:0/96"),  # RFC 2765 IPv4-translatable (SIIT)
    ipaddress.ip_network("::/96"),  # deprecated IPv4-compatible
)


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address ``addr`` carries, across every standard embedding form, or
    ``None`` if it embeds none."""
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr.sixtofour is not None:
        return addr.sixtofour
    if any(addr in net for net in _LOW32_EMBEDDING_NETS):
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


def _is_safe_global(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """An address is safe only if it is global *and* any IPv4 it embeds is itself
    global. Several IPv6 embedding forms report ``is_global`` even when they
    tunnel to a loopback/metadata IPv4, so the embedded address is the real
    check."""
    if not addr.is_global:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(addr)
        if embedded is not None and not embedded.is_global:
            return False
    return True


def sign(task_id: str, body: bytes, secret: bytes) -> str:
    """HMAC-SHA256 binding ``task_id`` to the raw body, so a completion signed for
    one task cannot be replayed against another."""
    return hmac.new(secret, task_id.encode() + b"\n" + body, sha256).hexdigest()


def _is_safe_global_str(ip: str) -> bool:
    """``_is_safe_global`` over a resolver string, failing closed on a value
    ``ipaddress`` cannot parse (e.g. a zone/scope suffix like ``fe80::1%eth0``)
    rather than letting the ``ValueError`` escape as a 500."""
    try:
        return _is_safe_global(ipaddress.ip_address(ip))
    except ValueError:
        return False


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
    if not addresses or any(not _is_safe_global_str(ip) for ip in addresses):
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
