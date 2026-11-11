"""Entry point: ``ingest-gateway``."""

from __future__ import annotations

import asyncio
import json

from pydantic import SecretStr

from aiops_common.bus import make_bus
from aiops_common.config import ServiceSettings
from aiops_common.runner import Worker
from ingest_gateway.app import Ingest, create_app


class Settings(ServiceSettings):
    service_name: str = "ingest-gateway"
    tenant_keys: SecretStr = SecretStr("{}")  # {"tenant": "<sha256 of api key>"}
    require_auth: bool = True


def main() -> None:
    s = Settings()
    bus = make_bus(s.kafka)
    ing = Ingest(bus, json.loads(s.tenant_keys.get_secret_value()), s.require_auth)
    w = Worker(s, bus)
    w.app = create_app(ing, w.ready)
    asyncio.run(w.serve())


if __name__ == "__main__":
    main()
