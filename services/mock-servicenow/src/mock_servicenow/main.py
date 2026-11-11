"""Entry point: ``mock-servicenow`` (dev/test only)."""

from __future__ import annotations

import os

import uvicorn

from mock_servicenow.app import create_app


def main() -> None:
    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))  # noqa: S104


if __name__ == "__main__":
    main()
