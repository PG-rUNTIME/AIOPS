"""Entry point: ``detector-workers``."""

from __future__ import annotations

import asyncio

from aiops_common.bus import Subscription, make_bus
from aiops_common.config import ServiceSettings
from aiops_common.contracts.registry import Topics
from aiops_common.runner import Worker
from detector_workers.forecast import make_forecaster
from detector_workers.rules import load_rules
from detector_workers.worker import DetectorWorker


class Settings(ServiceSettings):
    service_name: str = "detector-workers"
    detector_rules_file: str | None = None
    forecaster: str = "chronos2"  # chronos2 | stat
    chronos_model: str = "amazon/chronos-2"
    consumer_group: str = "detector-workers"


def main() -> None:
    s = Settings()
    bus = make_bus(s.kafka)
    dw = DetectorWorker(
        bus, load_rules(s.detector_rules_file), make_forecaster(s.forecaster, s.chronos_model)
    )
    bus.subscribe(Subscription([Topics.METRICS, Topics.LOGS], s.consumer_group, dw.on_event))
    asyncio.run(Worker(s, bus).serve())


if __name__ == "__main__":
    main()
