# `-m pocs.…` needs cwd = repo root so the `pocs` package is importable.
.PHONY: demo teardown
demo:
	cd ../.. && uv run python -m pocs.routing_hijack.exploit
teardown:
	@echo "No persistent state; nothing to tear down."
