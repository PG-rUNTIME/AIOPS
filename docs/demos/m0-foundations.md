# M0 demo — foundations

```bash
uv sync --all-packages
make lint typecheck            # ruff + mypy --strict
make contracts-check           # committed JSON Schemas / AsyncAPI / OpenAPI match the models
uv run pytest libs tests/test_contracts.py -v
```
Expect: all green; `contracts/` unchanged.
