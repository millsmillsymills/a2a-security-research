.PHONY: demo test lint

demo:
	$(MAKE) -C pocs/routing_hijack demo
	$(MAKE) -C pocs/webhook_ssrf demo

test:
	uv run pytest

lint:
	uv run ruff check . && uv run ty check
