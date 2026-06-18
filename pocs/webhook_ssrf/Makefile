# `-m pocs.…` needs cwd = repo root so the `pocs` package is importable.
.PHONY: demo teardown
demo:
	cd ../.. && uv run python -m pocs.webhook_ssrf.exploit
teardown:
	@echo "Demo servers are daemon threads torn down on exit; nothing persists."
