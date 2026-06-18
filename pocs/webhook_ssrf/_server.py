# pocs/webhook_ssrf/_server.py
"""Run a Starlette app on loopback in a background thread; stop it on demand."""

import threading
import time

import uvicorn
from starlette.applications import Starlette


def start(app: Starlette, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    return server, thread


def stop(server: uvicorn.Server, thread: threading.Thread) -> None:
    server.should_exit = True
    thread.join(timeout=5)
